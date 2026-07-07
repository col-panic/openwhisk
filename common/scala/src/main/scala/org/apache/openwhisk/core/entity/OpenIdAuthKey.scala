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

package org.apache.openwhisk.core.entity

import org.apache.pekko.http.scaladsl.model.headers.HttpCredentials
import spray.json._

/**
 * Authentication key for OpenID Connect authentication.
 *
 * @param uuid the uuid of the OpenID user
 * @param token the JWT token (may be empty for stored identities)
 */
protected[core] case class OpenIdAuthKey(uuid: UUID, token: String)
    extends GenericAuthKey(JsObject("openid" -> s"${uuid.asString}".toJson)) {
  override def toString: String = uuid.toString
  override def getCredentials: Option[HttpCredentials] = None
}

protected[core] object OpenIdAuthKey {

  /**
   * Creates an OpenIdAuthKey with a randomly generated UUID.
   */
  protected[core] def apply(): OpenIdAuthKey = new OpenIdAuthKey(UUID(), "")

  /**
   * Creates an OpenIdAuthKey from a UUID.
   */
  protected[core] def apply(uuid: UUID): OpenIdAuthKey = new OpenIdAuthKey(uuid, "")
}
