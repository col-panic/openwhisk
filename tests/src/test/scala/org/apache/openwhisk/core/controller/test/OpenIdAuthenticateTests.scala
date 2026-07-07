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

import org.apache.pekko.http.scaladsl.model.headers.{Authorization, OAuth2BearerToken, RawHeader}
import org.apache.openwhisk.common.{Logging, TransactionId}
import org.apache.openwhisk.core.ConfigKeys
import org.apache.openwhisk.core.controller.OpenIdAuthenticationDirective
import org.apache.openwhisk.core.database.NoDocumentException
import org.apache.openwhisk.core.entity._
import org.apache.openwhisk.core.entity.types.AuthStore
import org.apache.openwhisk.test.CommonTestUtilities
import org.scalatest.BeforeAndAfterAll
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.time.{Millis, Seconds, Span}
import org.scalatest.{FlatSpec, Matchers}
import pureconfig._
import pureconfig.generic.auto._
import spray.json._
import spray.json.DefaultJsonProtocol._

import scala.concurrent.duration.DurationInt
import scala.concurrent.{Await, ExecutionContext, Future}

class OpenIdAuthenticateTests
    extends FlatSpec
    with Matchers
    with ScalaFutures
    with BeforeAndAfterAll
    with CommonTestUtilities {

  implicit val ec = ExecutionContext.global
  implicit val transid = TransactionId.testing
  implicit val logging = new Logging {
    override def getMarkerString: String = "OpenIdAuthenticateTests"
    override def isTraceEnabled(marker: org.slf4j.Marker): Boolean = false
    override def trace(marker: org.slf4j.Marker, message: String): Unit = {}
    override def trace(marker: org.slf4j.Marker, message: String, t: Throwable): Unit = {}
    override def trace(marker: org.slf4j.Marker, format: String, arg1: Any): Unit = {}
    override def trace(marker: org.slf4j.Marker, format: String, arg1: Any, arg2: Any): Unit = {}
    override def trace(marker: org.slf4j.Marker, format: String, args: Any*): Unit = {}
    override def isDebugEnabled(marker: org.slf4j.Marker): Boolean = true
    override def debug(marker: org.slf4j.Marker, message: String): Unit = println(s"DEBUG: $message")
    override def debug(marker: org.slf4j.Marker, message: String, t: Throwable): Unit = println(s"DEBUG: $message, ${t.getMessage}")
    override def debug(marker: org.slf4j.Marker, format: String, arg1: Any): Unit = println(s"DEBUG: $format $arg1")
    override def debug(marker: org.slf4j.Marker, format: String, arg1: Any, arg2: Any): Unit = println(s"DEBUG: $format $arg1 $arg2")
    override def debug(marker: org.slf4j.Marker, format: String, args: Any*): Unit = println(s"DEBUG: $format ${args.mkString}")
    override def isInfoEnabled(marker: org.slf4j.Marker): Boolean = true
    override def info(marker: org.slf4j.Marker, message: String): Unit = println(s"INFO: $message")
    override def info(marker: org.slf4j.Marker, message: String, t: Throwable): Unit = println(s"INFO: $message, ${t.getMessage}")
    override def info(marker: org.slf4j.Marker, format: String, arg1: Any): Unit = println(s"INFO: $format $arg1")
    override def info(marker: org.slf4j.Marker, format: String, arg1: Any, arg2: Any): Unit = println(s"INFO: $format $arg1 $arg2")
    override def info(marker: org.slf4j.Marker, format: String, args: Any*): Unit = println(s"INFO: $format ${args.mkString}")
    override def isWarnEnabled(marker: org.slf4j.Marker): Boolean = true
    override def warn(marker: org.slf4j.Marker, message: String): Unit = println(s"WARN: $message")
    override def warn(marker: org.slf4j.Marker, message: String, t: Throwable): Unit = println(s"WARN: $message, ${t.getMessage}")
    override def warn(marker: org.slf4j.Marker, format: String, arg1: Any): Unit = println(s"WARN: $format $arg1")
    override def warn(marker: org.slf4j.Marker, format: String, arg1: Any, arg2: Any): Unit = println(s"WARN: $format $arg1 $arg2")
    override def warn(marker: org.slf4j.Marker, format: String, args: Any*): Unit = println(s"WARN: $format ${args.mkString}")
    override def isErrorEnabled(marker: org.slf4j.Marker): Boolean = true
    override def error(marker: org.slf4j.Marker, message: String): Unit = println(s"ERROR: $message")
    override def error(marker: org.slf4j.Marker, message: String, t: Throwable): Unit = println(s"ERROR: $message, ${t.getMessage}")
    override def error(marker: org.slf4j.Marker, format: String, arg1: Any): Unit = println(s"ERROR: $format $arg1")
    override def error(marker: org.slf4j.Marker, format: String, arg1: Any, arg2: Any): Unit = println(s"ERROR: $format $arg1 $arg2")
    override def error(marker: org.slf4j.Marker, format: String, args: Any*): Unit = println(s"ERROR: $format ${args.mkString}")
  }

  val authStore = WhiskAuthStore.datastore()

  // Test JWT token (base64 encoded header.payload.signature)
  // This is a mock token with issuer and sub claims
  val testJwtPayload = JsObject(
    "iss" -> "http://localhost:8080/auth/realms/master".toJson,
    "sub" -> "1234567890".toJson,
    "name" -> "Test User".toJson,
    "email" -> "test@example.com".toJson
  )

  // Base64 URL encode the payload
  val payloadBase64 = java.util.Base64.getUrlEncoder.withoutPadding.encodeToString(testJwtPayload.compactPrint.getBytes("UTF-8"))
  val headerBase64 = java.util.Base64.getUrlEncoder.withoutPadding.encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes("UTF-8"))
  val signatureBase64 = java.util.Base64.getUrlEncoder.withoutPadding.encodeToString("test-signature".getBytes("UTF-8"))
  val testJwtToken = s"$headerBase64.$payloadBase64.$signatureBase64"

  override protected def afterAll(): Unit = {
    authStore.shutdown()
  }

  behavior of "OpenID Authentication"

  it should "extract JWT token from Authorization header" in {
    val headers = Seq(Authorization(OAuth2BearerToken(testJwtToken)))
    val result = OpenIdAuthenticationDirective.extractJwtToken(headers)
    result shouldBe Some(testJwtToken)
  }

  it should "extract JWT token from X-Auth-Token header" in {
    val headers = Seq(RawHeader("X-Auth-Token", testJwtToken))
    val result = OpenIdAuthenticationDirective.extractJwtToken(headers)
    result shouldBe Some(testJwtToken)
  }

  it should "prefer Authorization header over X-Auth-Token header" in {
    val headers = Seq(
      RawHeader("X-Auth-Token", "token2"),
      Authorization(OAuth2BearerToken(testJwtToken))
    )
    val result = OpenIdAuthenticationDirective.extractJwtToken(headers)
    result shouldBe Some(testJwtToken)
  }

  it should "return None when no JWT token is present" in {
    val headers = Seq(RawHeader("Content-Type", "application/json"))
    val result = OpenIdAuthenticationDirective.extractJwtToken(headers)
    result shouldBe None
  }

  it should "decode JWT payload" in {
    val result = OpenIdAuthenticationDirective.decodeJwtPayload(testJwtToken)
    result shouldBe defined
    result.get.fields("iss") shouldBe Some(JsString("http://localhost:8080/auth/realms/master"))
    result.get.fields("sub") shouldBe Some(JsString("1234567890"))
  }

  it should "return None for malformed JWT" in {
    val malformedToken = "not.a.valid.jwt.token"
    val result = OpenIdAuthenticationDirective.decodeJwtPayload(malformedToken)
    result shouldBe None
  }

  // Note: Full integration tests would require a running CouchDB instance
  // and proper configuration, so we'll skip those for now

  it should "create OpenIdAuthKey" in {
    val uuid = UUID("1234567890")
    val authKey = OpenIdAuthKey(uuid)
    authKey.uuid shouldBe uuid
    authKey.toString shouldBe uuid.toString
  }

  it should "create WhiskNamespace with OpenIdAuthKey" in {
    val namespace = Namespace(EntityName("test-namespace"), UUID("1234567890"))
    val authKey = OpenIdAuthKey(UUID("1234567890"))
    val whiskNamespace = WhiskNamespace(namespace, authKey)
    whiskNamespace.namespace shouldBe namespace
    whiskNamespace.authkey shouldBe authKey
  }
}
