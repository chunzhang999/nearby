// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "fastpair/common/fast_pair_device.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "protobuf-matchers/protocol-buffer-matchers.h"
#include "gtest/gtest.h"
#include "fastpair/common/account_key.h"
#include "fastpair/common/protocol.h"

namespace nearby {
namespace fastpair {
namespace {

TEST(FastPairDevice, GetAndSetAccountKey) {
  FastPairDevice device("model_id", "ble_address",
                        Protocol::kFastPairInitialPairing);
  AccountKey firstKey = AccountKey::CreateRandomKey();
  device.SetAccountKey(firstKey);
  EXPECT_EQ(device.GetAccountKey(), firstKey);

  // Test that overriding works.
  AccountKey secondKey = AccountKey::CreateRandomKey();
  device.SetAccountKey(secondKey);
  EXPECT_EQ(device.GetAccountKey(), secondKey);
}

TEST(FastPairDevice, GetAndSetName) {
  FastPairDevice device("model_id", "ble_address",
                        Protocol::kFastPairInitialPairing);
  // Test that name returns null before any sets.
  std::optional<std::string> name = device.display_name();
  EXPECT_FALSE(name.has_value());

  // Test that name returns the set value.
  std::string test_name = "test_name";
  device.set_display_name(test_name);
  name = device.display_name();
  EXPECT_TRUE(name.has_value());
  EXPECT_EQ(name.value(), test_name);

  // Test that overriding works.
  std::string new_test_name = "new_test_name";
  device.set_display_name(new_test_name);
  name = device.display_name();
  EXPECT_TRUE(name.has_value());
  EXPECT_EQ(name.value(), new_test_name);
}

TEST(FastPairDevice, GetAndPublicAddress) {
  FastPairDevice device("model_id", "ble_address",
                        Protocol::kFastPairInitialPairing);
  // Test that public address returns null before any sets.
  std::optional<std::string> public_address = device.public_address();
  EXPECT_FALSE(public_address.has_value());

  // Test that name returns the set value.
  std::string test_public_address = "test_public_address ";
  device.set_public_address(test_public_address);
  public_address = device.public_address();
  EXPECT_TRUE(public_address.has_value());
  EXPECT_EQ(public_address.value(), test_public_address);

  // Test that overriding works.
  std::string new_test_public_address = "new_test_public_address ";
  device.set_public_address(new_test_public_address);
  public_address = device.public_address();
  EXPECT_TRUE(public_address.has_value());
  EXPECT_EQ(public_address.value(), new_test_public_address);
}

}  // namespace
}  // namespace fastpair
}  // namespace nearby
