// Copyright 2023 Google LLC
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

#include "presence/presence_device_provider.h"

#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "protobuf-matchers/protocol-buffer-matchers.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "internal/interop/authentication_transport.h"
#include "internal/interop/device_provider.h"
#include "internal/platform/implementation/credential_callbacks.h"
#include "internal/platform/implementation/system_clock.h"
#include "internal/proto/metadata.pb.h"
#include "internal/proto/metadata.proto.h"
#include "presence/implementation/mock_service_controller.h"
#include "presence/presence_device.h"

namespace nearby {
namespace presence {
namespace {
using ::nearby::internal::Metadata;

constexpr absl::string_view kMacAddr = "\x4C\x8B\x1D\xCE\xBA\xD1";

Metadata CreateTestMetadata() {
  Metadata metadata;
  metadata.set_device_type(internal::DEVICE_TYPE_PHONE);
  metadata.set_account_name("test_account");
  metadata.set_device_name("NP test device");
  metadata.set_user_name("Test user");
  metadata.set_device_profile_url("test_image.test.com");
  metadata.set_bluetooth_mac_address(kMacAddr);
  return metadata;
}

nearby::internal::LocalCredential CreateValidLocalCredential() {
  nearby::internal::LocalCredential credential;
  absl::Time now = SystemClock::ElapsedRealtime();
  credential.set_start_time_millis(absl::ToUnixMillis(now));
  credential.set_end_time_millis(absl::ToUnixMillis(now + absl::Minutes(10)));
  return credential;
}

nearby::internal::LocalCredential CreateInvalidLocalCredential() {
  nearby::internal::LocalCredential credential;
  absl::Time now = SystemClock::ElapsedRealtime();
  credential.set_start_time_millis(absl::ToUnixMillis(now - absl::Minutes(30)));
  credential.set_end_time_millis(absl::ToUnixMillis(now - absl::Minutes(10)));
  return credential;
}

class MockAuthenticationTransport : public AuthenticationTransport {
  MOCK_METHOD(void, WriteMessage, (absl::string_view), (const override));
  MOCK_METHOD(std::string, ReadMessage, (), (const override));
};

class PresenceDeviceProviderTest : public ::testing::Test {
 public:
  PresenceDeviceProviderTest() = default;
  ~PresenceDeviceProviderTest() override = default;

  void SetUp() override {
    ON_CALL(mock_service_controller_, GetLocalDeviceMetadata)
        .WillByDefault(testing::Return(CreateTestMetadata()));
    provider_ =
        std::make_unique<PresenceDeviceProvider>(&mock_service_controller_);
  }

 protected:
  MockServiceController mock_service_controller_;
  std::unique_ptr<PresenceDeviceProvider> provider_;
};

TEST_F(PresenceDeviceProviderTest, ProviderIsNotTriviallyConstructible) {
  EXPECT_FALSE(std::is_trivially_constructible<PresenceDeviceProvider>::value);
}

TEST_F(PresenceDeviceProviderTest, DeviceProviderWorks) {
  auto device = provider_->GetLocalDevice();
  ASSERT_EQ(device->GetType(), NearbyDevice::Type::kPresenceDevice);
  auto presence_device = static_cast<const PresenceDevice*>(device);
  EXPECT_EQ(presence_device->GetMetadata().SerializeAsString(),
            CreateTestMetadata().SerializeAsString());
}

TEST_F(PresenceDeviceProviderTest, DeviceProviderCanUpdateDevice) {
  auto device = provider_->GetLocalDevice();
  ASSERT_EQ(device->GetType(), NearbyDevice::Type::kPresenceDevice);
  auto presence_device = static_cast<const PresenceDevice*>(device);
  EXPECT_EQ(presence_device->GetMetadata().SerializeAsString(),
            CreateTestMetadata().SerializeAsString());
  Metadata new_metadata = CreateTestMetadata();
  new_metadata.set_device_name("NP interop device");
  provider_->UpdateMetadata(new_metadata);
  EXPECT_EQ(presence_device->GetMetadata().SerializeAsString(),
            new_metadata.SerializeAsString());
}

TEST_F(PresenceDeviceProviderTest,
       AuthenticateAsInitiatorFails_FailToFetchCredentials) {
  EXPECT_CALL(mock_service_controller_, GetLocalCredentials)
      .WillOnce([&](const CredentialSelector& credential_selector,
                    GetLocalCredentialsResultCallback callback) {
        std::move(callback.credentials_fetched_cb)(
            absl::Status(absl::StatusCode::kCancelled, /*msg=*/std::string()));
      });

  PresenceDevice remote_device{CreateTestMetadata()};
  MockAuthenticationTransport authentication_transport;
  auto status = provider_->AuthenticateAsInitiator(
      /*remote_device=*/remote_device, /*shared_secret=*/absl::string_view(),
      /*authentication_transport=*/authentication_transport);
  EXPECT_EQ(AuthenticationStatus::kFailure, status);
}

TEST_F(PresenceDeviceProviderTest,
       AuthenticateAsInitiatorFails_NoValidCredentials) {
  EXPECT_CALL(mock_service_controller_, GetLocalCredentials)
      .WillOnce([&](const CredentialSelector& credential_selector,
                    GetLocalCredentialsResultCallback callback) {
        std::vector<nearby::internal::LocalCredential> credentials;
        credentials.push_back(CreateInvalidLocalCredential());
        credentials.push_back(CreateInvalidLocalCredential());
        credentials.push_back(CreateInvalidLocalCredential());
        std::move(callback.credentials_fetched_cb)(credentials);
      });

  PresenceDevice remote_device{CreateTestMetadata()};
  MockAuthenticationTransport authentication_transport;
  auto status = provider_->AuthenticateAsInitiator(
      /*remote_device=*/remote_device, /*shared_secret=*/absl::string_view(),
      /*authentication_transport=*/authentication_transport);
  EXPECT_EQ(AuthenticationStatus::kFailure, status);
}

TEST_F(PresenceDeviceProviderTest, AuthenticateAsInitiatorSuccess) {
  EXPECT_CALL(mock_service_controller_, GetLocalCredentials)
      .WillOnce([&](const CredentialSelector& credential_selector,
                    GetLocalCredentialsResultCallback callback) {
        std::vector<nearby::internal::LocalCredential> credentials;
        credentials.push_back(CreateInvalidLocalCredential());
        credentials.push_back(CreateValidLocalCredential());
        credentials.push_back(CreateInvalidLocalCredential());
        std::move(callback.credentials_fetched_cb)(credentials);
      });

  PresenceDevice remote_device{CreateTestMetadata()};
  MockAuthenticationTransport authentication_transport;
  auto status = provider_->AuthenticateAsInitiator(
      /*remote_device=*/remote_device, /*shared_secret=*/absl::string_view(),
      /*authentication_transport=*/authentication_transport);

  // TODO(b/282027237): Once additional logic is added in follow up CL's
  // to continue the authentication, add coverage in this unit test for a
  // success case.
  EXPECT_EQ(AuthenticationStatus::kSuccess, status);
}

}  // namespace
}  // namespace presence
}  // namespace nearby
