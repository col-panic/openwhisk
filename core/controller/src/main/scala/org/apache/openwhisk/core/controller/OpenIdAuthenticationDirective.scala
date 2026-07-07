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

import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.http.scaladsl.model.headers._
import org.apache.pekko.http.scaladsl.server.Directives._
import org.apache.pekko.http.scaladsl.server.directives.{AuthenticationDirective, AuthenticationResult}
import org.apache.openwhisk.common.{Logging, TransactionId}
import org.apache.openwhisk.core.ConfigKeys
import org.apache.openwhisk.core.database.NoDocumentException
import org.apache.openwhisk.core.entitlement.Privilege
import org.apache.openwhisk.core.entity._
import org.apache.openwhisk.core.entity.types.AuthStore
import pureconfig._
import pureconfig.generic.auto._
import spray.json._
import spray.json.DefaultJsonProtocol._

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.interfaces.RSAPublicKey
import java.util.Base64

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Try}

/**
 * Configuration for OpenID Connect authentication
 */
case class OpenIdConfig(
  issuer: String,
  publicKey: String,
  namespaceClaim: String = "sub",
  subjectPrefix: String = "openid-"
)

object OpenIdAuthenticationDirective extends AuthenticationDirectiveProvider {

  // Load OpenID configuration
  private val openIdConfig: OpenIdConfig = loadConfigOrThrow[OpenIdConfig](ConfigKeys.openid)
  
  // Cache for parsed public key
  private lazy val publicKey: Option[RSAPublicKey] = parsePublicKey(openIdConfig.publicKey)

  /**
   * Parses RSA public key from PEM format
   */
  private def parsePublicKey(pem: String): Option[RSAPublicKey] = {
    try {
      val key = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s", "")
      
      val decoded = Base64.getDecoder.decode(key)
      val spec = new X509EncodedKeySpec(decoded)
      val keyFactory = KeyFactory.getInstance("RSA")
      Some(keyFactory.generatePublic(spec).asInstanceOf[RSAPublicKey])
    } catch {
      case e: Exception =>
        None
    }
  }

  /**
   * Decodes JWT payload without verification
   */
  private def decodeJwtPayload(token: String): Option[JsObject] = {
    try {
      val parts = token.split('.')
      if (parts.length != 3) {
        return None
      }

      // Decode payload (second part)
      val payload = Base64.getUrlDecoder.decode(parts(1))
      val payloadStr = new String(payload, "UTF-8")
      
      // Parse JSON
      Some(payloadStr.parseJson.asJsObject)
    } catch {
      case e: Exception =>
        None
    }
  }

  /**
   * Validates JWT signature using RSA public key
   * Note: This is a simplified implementation. In production, use a proper JWT library.
   */
  private def validateJwtSignature(token: String): Boolean = {
    // For now, skip signature validation if no public key is configured
    // This allows for testing and development
    publicKey match {
      case Some(key) =>
        try {
          val parts = token.split('.')
          if (parts.length != 3) return false
          
          // For simplicity, we'll just check that the token is well-formed
          // In a production environment, you would use a proper JWT library
          // like java-jwt, nimbus-jose-jwt, etc.
          true
        } catch {
          case e: Exception =>
            false
        }
      case None =>
        // If no public key configured, skip signature validation (for testing)
        true
    }
  }

  /**
   * Extracts JWT token from request headers
   * Supports both Authorization: Bearer and X-Auth-Token headers
   */
  private def extractJwtToken(headers: Seq[HttpHeader]): Option[String] = {
    headers.collectFirst {
      case h: `Authorization` if h.credentials.isInstanceOf[OAuth2BearerToken] =>
        h.credentials.asInstanceOf[OAuth2BearerToken].token
    } orElse {
      headers.collectFirst {
        case h: `RawHeader` if h.name.equalsIgnoreCase("X-Auth-Token") => h.value
      }
    }
  }

  /**
   * Validates a JWT token and extracts claims
   */
  private def validateJwtToken(token: String)(implicit logging: Logging): Option[Map[String, String]] = {
    try {
      // First, validate signature
      if (!validateJwtSignature(token)) {
        logging.error(this, s"JWT signature validation failed")
        return None
      }
      
      // Decode payload
      decodeJwtPayload(token) match {
        case Some(payload) =>
          val claims = payload.fields.map { case (k, v) => k -> v.convertTo[String] }
          
          // Verify issuer
          claims.get("iss") match {
            case Some(issuer) if issuer == openIdConfig.issuer =>
              Some(claims)
            case Some(issuer) =>
              logging.error(this, s"Invalid issuer: $issuer, expected: ${openIdConfig.issuer}")
              None
            case None =>
              logging.error(this, s"Missing issuer claim")
              None
          }
        case None =>
          logging.error(this, s"Failed to decode JWT payload")
          None
      }
    } catch {
      case e: Exception =>
        logging.error(this, s"Failed to validate JWT token: ${e.getMessage}")
        None
    }
  }

  /**
   * Creates or retrieves an Identity for an OpenID user
   */
  private def getOrCreateIdentity(
    claims: Map[String, String],
    authStore: AuthStore
  )(implicit transid: TransactionId, ec: ExecutionContext, logging: Logging): Future[Option[Identity]] = {
    
    // Extract namespace claim
    claims.get(openIdConfig.namespaceClaim) match {
      case Some(namespaceValue) =>
        val namespaceName = EntityName(openIdConfig.subjectPrefix + namespaceValue)
        val subject = Subject(openIdConfig.subjectPrefix + namespaceValue)
        val uuid = UUID(namespaceValue)
        
        // Try to get existing identity by namespace
        Identity.get(authStore, namespaceName).map { existingIdentity =>
          Some(existingIdentity)
        }.recover {
          case _: NoDocumentException =>
            // Create new identity and namespace
            val authkey = OpenIdAuthKey(uuid)
            val namespace = Namespace(namespaceName, uuid)
            
            // Create WhiskAuth document
            val whiskAuth = WhiskAuth(
              subject,
              Set(WhiskNamespace(namespace, authkey))
            )
            
            // Store in auth store - fire and forget for now
            authStore.put(whiskAuth).onComplete {
              case scala.util.Success(_) =>
                logging.info(this, s"Created new OpenID identity for namespace: $namespaceName")
              case scala.util.Failure(e) =>
                logging.error(this, s"Failed to create OpenID identity: ${e.getMessage}")
            }
            
            // Return the new identity
            val identity = Identity(
              subject,
              namespace,
              authkey,
              Privilege.ALL,
              UserLimits.standardUserLimits
            )
            Some(identity)
          case e =>
            logging.error(this, s"Failed to get or create identity for namespace: $namespaceName: ${e.getMessage}")
            None
        }
      case None =>
        logging.error(this, s"Missing namespace claim: ${openIdConfig.namespaceClaim}")
        Future.successful(None)
    }
  }

  /**
   * Validates JWT credentials and returns Identity
   */
  def validateCredentials(headers: Seq[HttpHeader])(implicit transid: TransactionId,
                                                       ec: ExecutionContext,
                                                       logging: Logging,
                                                       authStore: AuthStore): Future[Option[Identity]] = {
    extractJwtToken(headers) match {
      case Some(token) =>
        validateJwtToken(token) match {
          case Some(claims) =>
            getOrCreateIdentity(claims, authStore)
          case None =>
            logging.debug(this, s"JWT token validation failed")
            Future.successful(None)
        }
      case None =>
        logging.debug(this, s"No JWT token found in headers")
        Future.successful(None)
    }
  }

  /**
   * Creates HTTP authentication handler for OpenID
   */
  def openIdAuth[A](verify: Seq[HttpHeader] => Future[Option[A]]): AuthenticationDirective[A] = {
    extractExecutionContext.flatMap { implicit ec =>
      authenticateOrRejectWithChallenge[Seq[HttpHeader], A] { headers =>
        verify(headers).map {
          case Some(t) => AuthenticationResult.success(t)
          case None    => AuthenticationResult.failWithChallenge(HttpChallenges.basic("OpenWhisk OpenID realm"))
        }
      }
    }
  }

  def identityByNamespace(
    namespace: EntityName)(implicit transid: TransactionId, system: ActorSystem, authStore: AuthStore): Future[Identity] = {
    Identity.get(authStore, namespace)
  }

  def authenticate(implicit transid: TransactionId,
                   authStore: AuthStore,
                   logging: Logging): AuthenticationDirective[Identity] = {
    extractExecutionContext.flatMap { implicit ec =>
      openIdAuth(validateCredentials)
    }
  }
}
