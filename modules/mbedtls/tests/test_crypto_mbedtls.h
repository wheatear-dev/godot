/**************************************************************************/
/*  test_crypto_mbedtls.h                                                 */
/**************************************************************************/
/*                         This file is part of:                          */
/*                             GODOT ENGINE                               */
/*                        https://godotengine.org                         */
/**************************************************************************/
/* Copyright (c) 2014-present Godot Engine contributors (see AUTHORS.md). */
/* Copyright (c) 2007-2014 Juan Linietsky, Ariel Manzur.                  */
/*                                                                        */
/* Permission is hereby granted, free of charge, to any person obtaining  */
/* a copy of this software and associated documentation files (the        */
/* "Software"), to deal in the Software without restriction, including    */
/* without limitation the rights to use, copy, modify, merge, publish,    */
/* distribute, sublicense, and/or sell copies of the Software, and to     */
/* permit persons to whom the Software is furnished to do so, subject to  */
/* the following conditions:                                              */
/*                                                                        */
/* The above copyright notice and this permission notice shall be         */
/* included in all copies or substantial portions of the Software.        */
/*                                                                        */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,        */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF     */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. */
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY   */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,   */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE      */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                 */
/**************************************************************************/

#ifndef TEST_CRYPTO_MBEDTLS_H
#define TEST_CRYPTO_MBEDTLS_H

#include "core/crypto/crypto.h"
#include "core/crypto/hashing_context.h"

#include "tests/test_macros.h"
#include "tests/test_utils.h"

namespace TestCryptoMbedTLS {

void hmac_digest_test(HashingContext::HashType ht, String expected_hex);

TEST_CASE("[CryptoMbedTLS] HMAC digest") {
	// SHA-256
	hmac_digest_test(HashingContext::HashType::HASH_SHA256, "fe442023f8a7d36a810e1e7cd8a8e2816457f350a008fbf638296afa12085e59");

	// SHA-1
	hmac_digest_test(HashingContext::HashType::HASH_SHA1, "a0ac4cd68a2f4812c355983d94e8d025afe7dddf");
}

void hmac_context_digest_test(HashingContext::HashType ht, String expected_hex);

TEST_CASE("[HMACContext] HMAC digest") {
	// SHA-256
	hmac_context_digest_test(HashingContext::HashType::HASH_SHA256, "fe442023f8a7d36a810e1e7cd8a8e2816457f350a008fbf638296afa12085e59");

	// SHA-1
	hmac_context_digest_test(HashingContext::HashType::HASH_SHA1, "a0ac4cd68a2f4812c355983d94e8d025afe7dddf");
}

void crypto_key_public_only_test(String key_path, bool public_only);

TEST_CASE("[Crypto] CryptoKey private public_only") {
	const String priv_key_path = TestUtils::get_data_path("crypto/in.key");
	crypto_key_public_only_test(priv_key_path, false);
}

TEST_CASE("[Crypto] CryptoKey public public_only") {
	const String pub_key_path = TestUtils::get_data_path("crypto/in.pub");
	crypto_key_public_only_test(pub_key_path, true);
}

// TEST_CASE("[Crypto] CryptoKey save private") {
// 	const Ref<CryptoKey> crypto_key = create_crypto_key();
// 	const String priv_out_path = TestUtils::get_data_path("crypto/out.key");
// 	crypto_key->save(priv_out_path);
// 	const String priv_path = TestUtils::get_data_path("crypto/in.key");
// 	Ref<FileAccess> f_priv_out = FileAccess::open(priv_out_path, FileAccess::READ);
// 	REQUIRE(!f_priv_out.is_null());
// 	String s_priv_out = f_priv_out->get_as_utf8_string();
// 	Ref<FileAccess> f_priv_in = FileAccess::open(priv_path, FileAccess::READ);
// 	String s_priv_in = f_priv_in->get_as_utf8_string();
// 	CHECK(s_priv_out == s_priv_in);
// }

// TEST_CASE("[Crypto] CryptoKey save public") {
// 	const Ref<CryptoKey> crypto_key = create_crypto_key();
// 	const String pub_out_path = TestUtils::get_data_path("crypto/out.pub");
// 	crypto_key->save(pub_out_path, true);
// 	const String pub_path = TestUtils::get_data_path("crypto/in.pub");
// 	Ref<FileAccess> f_pub_out = FileAccess::open(pub_out_path, FileAccess::READ);
// 	REQUIRE(!f_pub_out.is_null());
// 	String s_pub_out = f_pub_out->get_as_utf8_string();
// 	Ref<FileAccess> f_pub_in = FileAccess::open(pub_path, FileAccess::READ);
// 	String s_pub_in = f_pub_in->get_as_utf8_string();
// 	CHECK(s_pub_out == s_pub_in);
// }
} // namespace TestCryptoMbedTLS

#endif // TEST_CRYPTO_MBEDTLS_H
