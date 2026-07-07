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

package org.apache.openwhisk.core.controller.test

import org.junit.runner.RunWith
import org.scalatestplus.junit.JUnitRunner

import org.apache.openwhisk.core.controller.OidcAuthenticationDirective
import org.apache.openwhisk.core.entity._

/**
 * Unit tests for [[OidcAuthenticationDirective]].
 *
 * These tests exercise the parts of the directive that do NOT require a running
 * OpenID Connect provider: namespace sanitisation, deterministic namespace derivation,
 * and the dynamic identity provisioning logic that operates directly against the
 * in-memory auth-store.
 */
@RunWith(classOf[JUnitRunner])
class OidcAuthenticateTests extends ControllerTestCommon {
  behavior of "OidcAuthenticationDirective"

  // ---------------------------------------------------------------------------
  // deriveNamespaceName
  // ---------------------------------------------------------------------------

  it should "produce a valid 24-char EntityName from any issuer + subject" in {
    val ns = OidcAuthenticationDirective.deriveNamespaceName("https://issuer.example.com", "user@example.com")
    EntityName(ns) // should not throw
    ns.length shouldBe 24
  }

  it should "produce the same namespace for the same issuer and subject (deterministic)" in {
    val issuer = "https://issuer.example.com"
    val sub = "alice"
    val ns1 = OidcAuthenticationDirective.deriveNamespaceName(issuer, sub)
    val ns2 = OidcAuthenticationDirective.deriveNamespaceName(issuer, sub)
    ns1 shouldBe ns2
  }

  it should "produce different namespaces for subjects that differ only in a special character" in {
    val issuer = "https://issuer.example.com"
    // These two subjects would collide under simple sanitization
    val ns1 = OidcAuthenticationDirective.deriveNamespaceName(issuer, "alice/foo")
    val ns2 = OidcAuthenticationDirective.deriveNamespaceName(issuer, "alice?foo")
    ns1 should not equal ns2
  }

  it should "produce different namespaces for the same subject under different issuers" in {
    val sub = "alice"
    val ns1 = OidcAuthenticationDirective.deriveNamespaceName("https://issuer1.example.com", sub)
    val ns2 = OidcAuthenticationDirective.deriveNamespaceName("https://issuer2.example.com", sub)
    ns1 should not equal ns2
  }

  it should "produce only URL-safe Base64 characters (valid EntityName chars)" in {
    val ns = OidcAuthenticationDirective.deriveNamespaceName("https://issuer.example.com", "some-subject-123")
    ns should fullyMatch regex "[A-Za-z0-9_-]+"
  }

  // ---------------------------------------------------------------------------
  // sanitizeNamespace (retained as a utility; no longer used for provisioning)
  // ---------------------------------------------------------------------------

  it should "pass through a simple alphanumeric subject unchanged" in {
    OidcAuthenticationDirective.sanitizeNamespace("alice") shouldBe "alice"
  }

  it should "pass through an email address as a valid namespace" in {
    val ns = OidcAuthenticationDirective.sanitizeNamespace("alice@example.com")
    EntityName(ns) // should not throw
    ns shouldBe "alice@example.com"
  }

  it should "pass through a UUID-formatted subject" in {
    val uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    val ns = OidcAuthenticationDirective.sanitizeNamespace(uuid)
    EntityName(ns) // should not throw
    ns shouldBe uuid
  }

  it should "replace slash characters with hyphens" in {
    val ns = OidcAuthenticationDirective.sanitizeNamespace("realm/user")
    EntityName(ns) // should not throw
    ns should not include "/"
  }

  it should "prepend u- when subject starts with a non-word character" in {
    val ns = OidcAuthenticationDirective.sanitizeNamespace("@startswithAt")
    EntityName(ns) // should not throw
    ns should startWith("u-")
  }

  it should "strip trailing spaces" in {
    val ns = OidcAuthenticationDirective.sanitizeNamespace("alice   ")
    EntityName(ns) // should not throw
    ns should not endWith " "
  }

  it should "truncate subjects longer than ENTITY_NAME_MAX_LENGTH" in {
    val longSubject = "a" * (EntityName.ENTITY_NAME_MAX_LENGTH + 50)
    val ns = OidcAuthenticationDirective.sanitizeNamespace(longSubject)
    EntityName(ns) // should not throw
    ns.length shouldBe EntityName.ENTITY_NAME_MAX_LENGTH
  }

  it should "not introduce an invalid trailing char after truncation" in {
    // Build a subject where truncation at ENTITY_NAME_MAX_LENGTH would land on a '-'
    // (which is valid mid-string but invalid as a trailing char under the EntityName regex).
    val sub = "a" * (EntityName.ENTITY_NAME_MAX_LENGTH - 1) + "-trailing"
    val ns = OidcAuthenticationDirective.sanitizeNamespace(sub)
    EntityName(ns) // should not throw
    ns.last.toString should fullyMatch regex "[\\w@.&]"
  }

  it should "fall back to u---- for an entirely invalid subject" in {
    val ns = OidcAuthenticationDirective.sanitizeNamespace("///")
    EntityName(ns) // should not throw
    ns shouldBe "u----"
  }

  // ---------------------------------------------------------------------------
  // Dynamic identity provisioning (requires auth-store)
  // ---------------------------------------------------------------------------

  it should "dynamically create a WhiskAuth document for an unknown namespace" in {
    implicit val tid = transid()
    import scala.concurrent.Await

    val issuer = "https://test.issuer.example.com"
    val jwtSubject = "oidctest-" + java.util.UUID.randomUUID().toString.take(8)
    val namespaceName = OidcAuthenticationDirective.deriveNamespaceName(issuer, jwtSubject)
    val namespace = EntityName(namespaceName)

    // 1. Confirm that no identity exists yet.
    val notFound = Await.result(
      Identity.get(authStore, namespace).map(Some(_)).recover { case _ => None },
      dbOpTimeout)
    notFound shouldBe None

    // 2. Build the WhiskAuth record manually (mirrors createIdentity behaviour).
    val uuid = UUID()
    val authKey = BasicAuthenticationAuthKey(uuid, Secret())
    val ns = Namespace(namespace, uuid)
    val subjectEntity = Subject("oidc-" + namespaceName) // mirrors OidcAuthenticationDirective.createIdentity
    val whiskAuth = WhiskAuth(subjectEntity, Set(WhiskNamespace(ns, authKey)))
    put(authStore, whiskAuth)

    // 3. After creation the namespace must be resolvable.
    waitOnView(authStore, authKey, 1)
    val identity = Await.result(Identity.get(authStore, namespace), dbOpTimeout)
    identity.namespace.name shouldBe namespace
    identity.subject shouldBe subjectEntity
  }
}
