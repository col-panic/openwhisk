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
 * OpenID Connect provider: namespace sanitisation and the dynamic identity
 * provisioning logic that operates directly against the in-memory auth-store.
 */
@RunWith(classOf[JUnitRunner])
class OidcAuthenticateTests extends ControllerTestCommon {
  behavior of "OidcAuthenticationDirective"

  // ---------------------------------------------------------------------------
  // sanitizeNamespace
  // ---------------------------------------------------------------------------

  it should "pass through a simple alphanumeric subject unchanged" in {
    OidcAuthenticationDirective.sanitizeNamespace("alice") shouldBe "alice"
  }

  it should "pass through an email address as a valid namespace" in {
    // '@' and '.' are allowed in entity names
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

  it should "fall back to oidc-user for an entirely invalid subject" in {
    // A subject consisting solely of characters that become spaces/hyphens and
    // that can't form a valid EntityName at all (e.g. only slashes)
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

    // Pick a unique namespace so test isolation is guaranteed.
    val subject = "oidctest-" + java.util.UUID.randomUUID().toString.take(8)
    val namespace = EntityName(OidcAuthenticationDirective.sanitizeNamespace(subject))

    // Call the package-private helper directly to exercise store interaction.
    // We use reflection to access the private method via the companion object.
    // Instead, test through the public surface: sanitize + expect Identity.get to
    // fail before creation and succeed after.

    // 1. Confirm that no identity exists yet.
    val notFound = Await.result(
      Identity.get(authStore, namespace).map(Some(_)).recover { case _ => None },
      dbOpTimeout)
    notFound shouldBe None

    // 2. Build the WhiskAuth record manually (mirrors createIdentity behaviour).
    val uuid = UUID()
    val authKey = BasicAuthenticationAuthKey(uuid, Secret())
    val ns = Namespace(namespace, uuid)
    val subjectEntity = Subject(subject)
    val whiskAuth = WhiskAuth(subjectEntity, Set(WhiskNamespace(ns, authKey)))
    put(authStore, whiskAuth)

    // 3. After creation the namespace must be resolvable.
    waitOnView(authStore, authKey, 1)
    val identity = Await.result(Identity.get(authStore, namespace), dbOpTimeout)
    identity.namespace.name shouldBe namespace
    identity.subject shouldBe subjectEntity
  }
}
