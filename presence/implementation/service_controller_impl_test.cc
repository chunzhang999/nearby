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

#include "presence/implementation/service_controller_impl.h"

#include <memory>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "protobuf-matchers/protocol-buffer-matchers.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "internal/platform/implementation/credential_callbacks.h"
#include "internal/proto/credential.pb.h"
#include "presence/implementation/credential_manager.h"
#include "presence/implementation/mock_credential_manager.h"
#include "presence/implementation/service_controller.h"

namespace nearby {
namespace presence {
namespace {

constexpr absl::string_view kManagerAppId = "TEST_MANAGER_APP";
constexpr absl::string_view kAccountName = "test account";

CredentialSelector BuildDefaultCredentialSelector() {
  CredentialSelector credential_selector;
  credential_selector.manager_app_id = std::string(kManagerAppId);
  credential_selector.account_name = std::string(kAccountName);
  credential_selector.identity_type =
      ::nearby::internal::IdentityType::IDENTITY_TYPE_PRIVATE;
  return credential_selector;
}

std::vector<internal::LocalCredential> BuildLocalCredentials() {
  internal::LocalCredential local_credential1;
  internal::LocalCredential local_credential2;
  internal::LocalCredential local_credential3;
  return {local_credential1, local_credential2, local_credential3};
}

class TestServiceController final : public ServiceControllerImpl {
 public:
  explicit TestServiceController(
      std::unique_ptr<CredentialManager> credential_manager)
      : ServiceControllerImpl(std::move(credential_manager)) {}
};

TEST(ServiceControllerImplTest, GetLocalCredentials) {
  auto mock_credential_manager = std::make_unique<MockCredentialManager>();
  EXPECT_CALL(*mock_credential_manager.get(), GetLocalCredentials)
      .WillOnce([&](const CredentialSelector& credential_selector,
                    GetLocalCredentialsResultCallback callback) {
        callback.credentials_fetched_cb(BuildLocalCredentials());
      });

  std::unique_ptr<ServiceController> service_controller =
      std::make_unique<TestServiceController>(
          std::move(mock_credential_manager));
  CredentialSelector credential_selector = BuildDefaultCredentialSelector();

  absl::StatusOr<std::vector<::nearby::internal::LocalCredential>>
      private_credentials;
  service_controller->GetLocalCredentials(
      credential_selector,
      {.credentials_fetched_cb =
           [&](absl::StatusOr<std::vector<::nearby::internal::LocalCredential>>
                   credentials) {
             private_credentials = std::move(credentials);
           }});

  EXPECT_OK(private_credentials);
  EXPECT_FALSE(private_credentials->empty());
}

}  // namespace
}  // namespace presence
}  // namespace nearby
