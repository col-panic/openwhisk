/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.openwhisk.core.controller

import java.net.URL
import java.util.{Arrays => JArrays, HashSet => JHashSet}

import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.{JWSAlgorithmFamilyJWSKeySelector, SecurityContext}
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.{DefaultJWTClaimsVerifier, DefaultJWTProcessor}
import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.http.scaladsl.model.headers._
import org.apache.pekko.http.scaladsl.server.Directives._
import org.apache.pekko.http.scaladsl.server.directives.{AuthenticationDirective, AuthenticationResult}
import org.apache.openwhisk.common.{Logging, TransactionId}
import org.apache.openwhisk.core.ConfigKeys
import org.apache.openwhisk.core.database.{CacheChangeNotification, DocumentConflictException, NoDocumentException}
import org.apache.openwhisk.core.entitlement.Privilege
import org.apache.openwhisk.core.entity._
import org.apache.openwhisk.core.entity.types.AuthStore
import pureconfig._
import pureconfig.generic.auto._

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success, Try}

/**
 * Authentication directive that supports OpenID Connect (OIDC) Bearer-token authentication
 * in addition to the existing HTTP Basic authentication.
 *
 * When a request carries an `Authorization: ****** header the token is validated
 * against the configured JWKS endpoint.  The subject is extracted from the JWT claim
 * named by `whisk.oidc.subject-claim` (default: `"sub"`), sanitised into a valid
 * OpenWhisk namespace name and then looked up in the auth-store.  If no record exists
 * yet, a new [[WhiskAuth]] document is created automatically so that the OIDC user can
 * start using the API immediately without any manual provisioning step.
 *
 * Requests that do not carry a ****** fall back to HTTP Basic authentication,
 * preserving full backwards-compatibility with existing API-key clients.
 *
 * To activate this directive set the following in your configuration:
 * {{{
 *   whisk.spi.AuthenticationDirectiveProvider = "org.apache.openwhisk.core.controller.OidcAuthenticationDirective"
 *   whisk.oidc {
 *     jwks-url      = "https://<your-idp>/.well-known/jwks.json"
 *     issuer        = "https://<your-idp>"
 *     audience      = "<your-audience>"   # optional – leave empty to skip audience check
 *     subject-claim = "sub"               # or "preferred_username" / "email"
 *   }
 * }}}
 */
object OidcAuthenticationDirective extends AuthenticationDirectiveProvider {

  /** Pureconfig-mapped representation of `whisk.oidc`. */
  private case class OidcConfig(jwksUrl: String, issuer: String, audience: String, subjectClaim: String)

  private lazy val oidcConfig: OidcConfig = loadConfigOrThrow[OidcConfig](ConfigKeys.oidc)

  /**
   * Lazily initialised, thread-safe JWT processor backed by a caching remote JWKS source.
   * Initialisation is deferred so that it only happens when OIDC auth is actually used.
   */
  private lazy val jwtProcessor: DefaultJWTProcessor[SecurityContext] = {
    val jwkSource = JWKSourceBuilder
      .create[SecurityContext](new URL(oidcConfig.jwksUrl))
      .build()

    val keySelector = JWSAlgorithmFamilyJWSKeySelector.fromJWKSource[SecurityContext](jwkSource)

    // Required claims: sub and exp must always be present.
    val requiredClaims = new JHashSet[String](JArrays.asList("sub", "exp"))

    // Exact-match claims: issuer is always checked; audience only when configured.
    val exactMatchClaims = new JWTClaimsSet.Builder().issuer(oidcConfig.issuer).build()

    // Accepted audiences – null means skip audience validation.
    val acceptedAudiences: java.util.Set[String] =
      if (oidcConfig.audience.nonEmpty) new JHashSet[String](JArrays.asList(oidcConfig.audience)) else null

    val claimsVerifier =
      new DefaultJWTClaimsVerifier[SecurityContext](acceptedAudiences, exactMatchClaims, requiredClaims, null)

    val processor = new DefaultJWTProcessor[SecurityContext]()
    processor.setJWSKeySelector(keySelector)
    processor.setJWTClaimsSetVerifier(claimsVerifier)
    processor
  }

  /**
   * Validates a raw JWT string and, on success, resolves (or dynamically creates) the
   * corresponding [[Identity]].
   */
  def validateBearerToken(token: String)(implicit transid: TransactionId,
                                         ec: ExecutionContext,
                                         logging: Logging,
                                         authStore: AuthStore): Future[Option[Identity]] = {
    Try(jwtProcessor.process(token, null)) match {
      case Failure(e) =>
        logging.debug(this, s"OIDC JWT validation failed: ${e.getMessage}")
        Future.successful(None)

      case Success(claims) =>
        val rawSubject = Option(claims.getStringClaim(oidcConfig.subjectClaim))
          .filter(_.nonEmpty)
          .getOrElse(claims.getSubject)

        if (rawSubject == null || rawSubject.isEmpty) {
          logging.warn(this, s"OIDC JWT contains no usable subject in claim '${oidcConfig.subjectClaim}'")
          Future.successful(None)
        } else {
          lookupOrCreateIdentity(rawSubject)
        }
    }
  }

  /**
   * Looks up an [[Identity]] by its derived namespace name.  If no entry exists in the
   * auth-store a new [[WhiskAuth]] document is created transparently (dynamic provisioning).
   * A concurrent creation conflict is resolved by retrying the lookup once.
   */
  private def lookupOrCreateIdentity(jwtSubject: String)(implicit transid: TransactionId,
                                                         ec: ExecutionContext,
                                                         logging: Logging,
                                                         authStore: AuthStore): Future[Option[Identity]] = {
    val namespaceName = sanitizeNamespace(jwtSubject)
    Try(EntityName(namespaceName)) match {
      case Failure(e) =>
        logging.warn(this, s"Cannot derive a valid namespace from OIDC subject '$jwtSubject': ${e.getMessage}")
        Future.successful(None)

      case Success(namespace) =>
        Identity
          .get(authStore, namespace)
          .map(identity => Some(identity))
          .recoverWith {
            case _: NoDocumentException =>
              createIdentity(jwtSubject, namespace).recoverWith {
                // Another request created the document concurrently – retry the lookup.
                case _: DocumentConflictException =>
                  Identity.get(authStore, namespace).map(Some(_)).recover {
                    case _: NoDocumentException => None
                  }
              }
          }
    }
  }

  /**
   * Creates a brand-new [[WhiskAuth]] record for an OIDC user that has not been seen
   * before, persists it to the auth-store and returns the resulting [[Identity]].
   */
  private def createIdentity(jwtSubject: String, namespace: EntityName)(
    implicit transid: TransactionId,
    ec: ExecutionContext,
    logging: Logging,
    authStore: AuthStore): Future[Option[Identity]] = {

    val uuid = UUID()
    val authKey = BasicAuthenticationAuthKey(uuid, Secret())
    val ns = Namespace(namespace, uuid)

    // Derive a valid Subject from the JWT subject.  Subject must be at least
    // Subject.MIN_LENGTH characters and consist of safe characters.
    val subjectStr = {
      val cleaned = jwtSubject.filter(c => c.isLetterOrDigit || c == '-' || c == '_' || c == '.' || c == '@')
      if (cleaned.length >= Subject.MIN_LENGTH) cleaned.take(256)
      else ("oidc-" + uuid.asString.filterNot(_ == '-')).take(32)
    }

    val subject = Try(Subject(subjectStr)).getOrElse(Subject())
    val whiskAuth = WhiskAuth(subject, Set(WhiskNamespace(ns, authKey)))

    implicit val notifier: Option[CacheChangeNotification] = None
    WhiskAuth
      .put(authStore, whiskAuth, None)
      .map { _ =>
        logging.info(this, s"Dynamically created namespace '${namespace.asString}' for OIDC subject '$jwtSubject'")
        Some(Identity(subject, ns, authKey, Privilege.ALL))
      }
  }

  /**
   * Converts a raw JWT subject string into a name that satisfies the [[EntityName]] regex:
   * {{{
   *   \A([\w]|[\w][\w@ .&-]{0,254}[\w@.&-])\z
   * }}}
   *
   *  1. Replace characters outside `[\w@ .&-]` with `-`.
   *  2. Ensure the string starts with a word character (prepend `u-` when needed).
   *  3. Strip trailing characters that are not in `[\w@.&-]` (e.g., spaces).
   *  4. Truncate to [[EntityName.ENTITY_NAME_MAX_LENGTH]].
   */
  private[controller] def sanitizeNamespace(subject: String): String = {
    // Step 1: replace invalid characters
    val replaced = subject.replaceAll("[^\\w@ .&-]", "-")

    // Step 2: ensure valid start (must be a word character)
    val validStart = if (replaced.nonEmpty && replaced.head.toString.matches("\\w")) replaced else "u-" + replaced

    // Step 3: strip trailing characters not in [\w@.&-]
    val validEnd = validStart.reverse.dropWhile(c => !c.toString.matches("[\\w@.&-]")).reverse

    // Step 4: truncate and fall back to a safe default if somehow still empty
    if (validEnd.nonEmpty) validEnd.take(EntityName.ENTITY_NAME_MAX_LENGTH) else "oidc-user"
  }

  /** Delegates to [[BasicAuthenticationDirective]] for web-action namespace lookups. */
  def identityByNamespace(namespace: EntityName)(implicit transid: TransactionId,
                                                 system: ActorSystem,
                                                 authStore: AuthStore): Future[Identity] =
    BasicAuthenticationDirective.identityByNamespace(namespace)

  /**
   * Returns a Pekko HTTP [[AuthenticationDirective]] that first tries Bearer-token
   * (OIDC JWT) authentication and falls back to HTTP Basic auth.
   */
  def authenticate(implicit transid: TransactionId,
                   authStore: AuthStore,
                   logging: Logging): AuthenticationDirective[Identity] = {
    extractExecutionContext.flatMap { implicit ec =>
      optionalHeaderValueByType(classOf[Authorization]).flatMap {
        case Some(Authorization(OAuth2BearerToken(token))) =>
          // ****** path: validate JWT and resolve identity
          authenticateOrRejectWithChallenge[OAuth2BearerToken, Identity] { _ =>
            validateBearerToken(token).map {
              case Some(identity) => AuthenticationResult.success(identity)
              case None           => AuthenticationResult.failWithChallenge(HttpChallenges.oAuth2("OpenWhisk secure realm"))
            }
          }

        case _ =>
          // No ****** fall back to HTTP Basic authentication
          BasicAuthenticationDirective.basicAuth(
            BasicAuthenticationDirective.validateCredentials(_)(transid, ec, logging, authStore))
      }
    }
  }
}
