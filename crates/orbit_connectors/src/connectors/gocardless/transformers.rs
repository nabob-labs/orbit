use common_enums::{enums, CountryAlpha2, UsStatesAbbreviation};
use common_utils::{
    id_type,
    pii::{self, IpAddress},
};
use orbit_domain_models::{
    address::AddressDetails,
    payment_method_data::{BankDebitData, PaymentMethodData},
    router_data::{ConnectorAuthType, PaymentMethodToken, RouterData},
    router_flow_types::refunds::Execute,
    router_request_types::{
        ConnectorCustomerData, PaymentMethodTokenizationData, PaymentsAuthorizeData,
        PaymentsSyncData, ResponseId, SetupMandateRequestData,
    },
    router_response_types::{MandateReference, PaymentsResponseData, RefundsResponseData},
    types,
};
use orbit_interfaces::{api, errors};
use masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{
        self, AddressDetailsData, BrowserInformationData, CustomerData, ForeignTryFrom,
        PaymentsAuthorizeRequestData, PaymentsSetupMandateRequestData, RouterData as _,
    },
};

pub struct GocardlessRouterData<T> {
    pub amount: i64, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T> TryFrom<(&api::CurrencyUnit, enums::Currency, i64, T)> for GocardlessRouterData<T> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (_currency_unit, _currency, amount, item): (&api::CurrencyUnit, enums::Currency, i64, T),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

#[derive(Default, Debug, Serialize)]
pub struct GocardlessCustomerRequest {
    customers: GocardlessCustomer,
}

#[derive(Default, Debug, Serialize)]
pub struct GocardlessCustomer {
    address_line1: Option<Secret<String>>,
    address_line2: Option<Secret<String>>,
    address_line3: Option<Secret<String>>,
    city: Option<Secret<String>>,
    region: Option<Secret<String>>,
    country_code: Option<CountryAlpha2>,
    email: pii::Email,
    given_name: Secret<String>,
    family_name: Secret<String>,
    metadata: CustomerMetaData,
    danish_identity_number: Option<Secret<String>>,
    postal_code: Option<Secret<String>>,
    swedish_identity_number: Option<Secret<String>>,
}

#[derive(Default, Debug, Serialize)]
pub struct CustomerMetaData {
    crm_id: Option<Secret<id_type::CustomerId>>,
}

impl TryFrom<&types::ConnectorCustomerRouterData> for GocardlessCustomerRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::ConnectorCustomerRouterData) -> Result<Self, Self::Error> {
        let email = item.request.get_email()?;
        let billing_details_name = item.get_billing_full_name()?.expose();

        let (given_name, family_name) = billing_details_name
            .trim()
            .rsplit_once(' ')
            .unwrap_or((&billing_details_name, &billing_details_name));

        let billing_address = item.get_billing_address()?;

        let metadata = CustomerMetaData {
            crm_id: item.customer_id.clone().map(Secret::new),
        };
        let region = get_region(billing_address)?;
        Ok(Self {
            customers: GocardlessCustomer {
                email,
                given_name: Secret::new(given_name.to_string()),
                family_name: Secret::new(family_name.to_string()),
                metadata,
                address_line1: billing_address.line1.to_owned(),
                address_line2: billing_address.line2.to_owned(),
                address_line3: billing_address.line3.to_owned(),
                country_code: billing_address.country,
                region,
                // Should be populated based on the billing country
                danish_identity_number: None,
                postal_code: billing_address.zip.to_owned(),
                // Should be populated based on the billing country
                swedish_identity_number: None,
                city: billing_address.city.clone().map(Secret::new),
            },
        })
    }
}

fn get_region(
    address_details: &AddressDetails,
) -> Result<Option<Secret<String>>, error_stack::Report<errors::ConnectorError>> {
    match address_details.country {
        Some(CountryAlpha2::US) => {
            let state = address_details.get_state()?.to_owned();
            Ok(Some(Secret::new(
                UsStatesAbbreviation::foreign_try_from(state.expose())?.to_string(),
            )))
        }
        _ => Ok(None),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GocardlessCustomerResponse {
    customers: Customers,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Customers {
    id: Secret<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            F,
            GocardlessCustomerResponse,
            ConnectorCustomerData,
            PaymentsResponseData,
        >,
    > for RouterData<F, ConnectorCustomerData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            F,
            GocardlessCustomerResponse,
            ConnectorCustomerData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::ConnectorCustomerResponse {
                connector_customer_id: item.response.customers.id.expose(),
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct GocardlessBankAccountRequest {
    customer_bank_accounts: CustomerBankAccounts,
}

#[derive(Debug, Serialize)]
pub struct CustomerBankAccounts {
    #[serde(flatten)]
    accounts: CustomerBankAccount,
    links: CustomerAccountLink,
}

#[derive(Debug, Serialize)]
pub struct CustomerAccountLink {
    customer: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CustomerBankAccount {
    InternationalBankAccount(InternationalBankAccount),
    AUBankAccount(AUBankAccount),
    USBankAccount(USBankAccount),
}

#[derive(Debug, Serialize)]
pub struct InternationalBankAccount {
    iban: Secret<String>,
    account_holder_name: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct AUBankAccount {
    country_code: CountryAlpha2,
    account_number: Secret<String>,
    branch_code: Secret<String>,
    account_holder_name: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct USBankAccount {
    country_code: CountryAlpha2,
    account_number: Secret<String>,
    bank_code: Secret<String>,
    account_type: AccountType,
    account_holder_name: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountType {
    Checking,
    Savings,
}

impl TryFrom<&types::TokenizationRouterData> for GocardlessBankAccountRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::TokenizationRouterData) -> Result<Self, Self::Error> {
        let customer = item.get_connector_customer_id()?;
        let accounts = CustomerBankAccount::try_from(item)?;
        let links = CustomerAccountLink {
            customer: Secret::new(customer),
        };
        Ok(Self {
            customer_bank_accounts: CustomerBankAccounts { accounts, links },
        })
    }
}

impl TryFrom<&types::TokenizationRouterData> for CustomerBankAccount {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::TokenizationRouterData) -> Result<Self, Self::Error> {
        match &item.request.payment_method_data {
            PaymentMethodData::BankDebit(bank_debit_data) => {
                Self::try_from((bank_debit_data, item))
            }
            PaymentMethodData::Card(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("Gocardless"),
                )
                .into())
            }
        }
    }
}

impl TryFrom<(&BankDebitData, &types::TokenizationRouterData)> for CustomerBankAccount {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (bank_debit_data, item): (&BankDebitData, &types::TokenizationRouterData),
    ) -> Result<Self, Self::Error> {
        match bank_debit_data {
            BankDebitData::AchBankDebit {
                account_number,
                routing_number,
                bank_type,
                ..
            } => {
                let bank_type = bank_type.ok_or_else(utils::missing_field_err("bank_type"))?;
                let country_code = item.get_billing_country()?;
                let account_holder_name = item.get_billing_full_name()?;
                let us_bank_account = USBankAccount {
                    country_code,
                    account_number: account_number.clone(),
                    bank_code: routing_number.clone(),
                    account_type: AccountType::from(bank_type),
                    account_holder_name,
                };
                Ok(Self::USBankAccount(us_bank_account))
            }
            BankDebitData::BecsBankDebit {
                account_number,
                bsb_number,
                ..
            } => {
                let country_code = item.get_billing_country()?;
                let account_holder_name = item.get_billing_full_name()?;
                let au_bank_account = AUBankAccount {
                    country_code,
                    account_number: account_number.clone(),
                    branch_code: bsb_number.clone(),
                    account_holder_name,
                };
                Ok(Self::AUBankAccount(au_bank_account))
            }
            BankDebitData::SepaBankDebit { iban, .. } => {
                let account_holder_name = item.get_billing_full_name()?;
                let international_bank_account = InternationalBankAccount {
                    iban: iban.clone(),
                    account_holder_name,
                };
                Ok(Self::InternationalBankAccount(international_bank_account))
            }
            BankDebitData::BacsBankDebit { .. } => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Gocardless"),
            )
            .into()),
        }
    }
}

impl From<common_enums::BankType> for AccountType {
    fn from(item: common_enums::BankType) -> Self {
        match item {
            common_enums::BankType::Checking => Self::Checking,
            common_enums::BankType::Savings => Self::Savings,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GocardlessBankAccountResponse {
    customer_bank_accounts: CustomerBankAccountResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomerBankAccountResponse {
    pub id: Secret<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            F,
            GocardlessBankAccountResponse,
            PaymentMethodTokenizationData,
            PaymentsResponseData,
        >,
    > for RouterData<F, PaymentMethodTokenizationData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            F,
            GocardlessBankAccountResponse,
            PaymentMethodTokenizationData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::TokenizationResponse {
                token: item.response.customer_bank_accounts.id.expose(),
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct GocardlessMandateRequest {
    mandates: Mandate,
}

#[derive(Debug, Serialize)]
pub struct Mandate {
    scheme: GocardlessScheme,
    metadata: MandateMetaData,
    payer_ip_address: Option<Secret<String, IpAddress>>,
    links: MandateLink,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GocardlessScheme {
    Becs,
    SepaCore,
    Ach,
    BecsNz,
}

#[derive(Debug, Serialize)]
pub struct MandateMetaData {
    payment_reference: String,
}

#[derive(Debug, Serialize)]
pub struct MandateLink {
    customer_bank_account: Secret<String>,
}

impl TryFrom<&types::SetupMandateRouterData> for GocardlessMandateRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::SetupMandateRouterData) -> Result<Self, Self::Error> {
        let (scheme, payer_ip_address) = match &item.request.payment_method_data {
            PaymentMethodData::BankDebit(bank_debit_data) => {
                let payer_ip_address = get_ip_if_required(bank_debit_data, item)?;
                Ok((
                    GocardlessScheme::try_from(bank_debit_data)?,
                    payer_ip_address,
                ))
            }
            PaymentMethodData::Card(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    "Setup Mandate flow for selected payment method through Gocardless".to_string(),
                ))
            }
        }?;
        let payment_method_token = item.get_payment_method_token()?;
        let customer_bank_account = match payment_method_token {
            PaymentMethodToken::Token(token) => Ok(token),
            PaymentMethodToken::ApplePayDecrypt(_)
            | PaymentMethodToken::PazeDecrypt(_)
            | PaymentMethodToken::GooglePayDecrypt(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    "Setup Mandate flow for selected payment method through Gocardless".to_string(),
                ))
            }
        }?;
        Ok(Self {
            mandates: Mandate {
                scheme,
                metadata: MandateMetaData {
                    payment_reference: item.connector_request_reference_id.clone(),
                },
                payer_ip_address,
                links: MandateLink {
                    customer_bank_account,
                },
            },
        })
    }
}

fn get_ip_if_required(
    bank_debit_data: &BankDebitData,
    item: &types::SetupMandateRouterData,
) -> Result<Option<Secret<String, IpAddress>>, error_stack::Report<errors::ConnectorError>> {
    let ip_address = item.request.get_browser_info()?.get_ip_address()?;
    match bank_debit_data {
        BankDebitData::AchBankDebit { .. } => Ok(Some(ip_address)),
        BankDebitData::SepaBankDebit { .. }
        | BankDebitData::BecsBankDebit { .. }
        | BankDebitData::BacsBankDebit { .. } => Ok(None),
    }
}

impl TryFrom<&BankDebitData> for GocardlessScheme {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &BankDebitData) -> Result<Self, Self::Error> {
        match item {
            BankDebitData::AchBankDebit { .. } => Ok(Self::Ach),
            BankDebitData::SepaBankDebit { .. } => Ok(Self::SepaCore),
            BankDebitData::BecsBankDebit { .. } => Ok(Self::Becs),
            BankDebitData::BacsBankDebit { .. } => Err(errors::ConnectorError::NotImplemented(
                "Setup Mandate flow for selected payment method through Gocardless".to_string(),
            )
            .into()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GocardlessMandateResponse {
    mandates: MandateResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MandateResponse {
    id: Secret<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            F,
            GocardlessMandateResponse,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    > for RouterData<F, SetupMandateRequestData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            F,
            GocardlessMandateResponse,
            SetupMandateRequestData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let mandate_reference = Some(MandateReference {
            connector_mandate_id: Some(item.response.mandates.id.clone().expose()),
            payment_method_id: None,
            mandate_metadata: None,
            connector_mandate_request_reference_id: None,
        });
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                connector_metadata: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                resource_id: ResponseId::NoResponseId,
                redirection_data: Box::new(None),
                mandate_reference: Box::new(mandate_reference),
                network_txn_id: None,
                charges: None,
            }),
            status: enums::AttemptStatus::Charged,
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct GocardlessPaymentsRequest {
    payments: GocardlessPayment,
}

#[derive(Debug, Serialize)]
pub struct GocardlessPayment {
    amount: i64,
    currency: enums::Currency,
    description: Option<String>,
    metadata: PaymentMetaData,
    links: PaymentLink,
}

#[derive(Debug, Serialize)]
pub struct PaymentMetaData {
    payment_reference: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentLink {
    mandate: Secret<String>,
}

impl TryFrom<&GocardlessRouterData<&types::PaymentsAuthorizeRouterData>>
    for GocardlessPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &GocardlessRouterData<&types::PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let mandate_id = if item.router_data.request.is_mandate_payment() {
            item.router_data
                .request
                .connector_mandate_id()
                .ok_or_else(utils::missing_field_err("mandate_id"))
        } else {
            Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("gocardless"),
            )
            .into())
        }?;
        let payments = GocardlessPayment {
            amount: item.router_data.request.amount,
            currency: item.router_data.request.currency,
            description: item.router_data.description.clone(),
            metadata: PaymentMetaData {
                payment_reference: item.router_data.connector_request_reference_id.clone(),
            },
            links: PaymentLink {
                mandate: Secret::new(mandate_id),
            },
        };
        Ok(Self { payments })
    }
}

// Auth Struct
pub struct GocardlessAuthType {
    pub(super) access_token: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for GocardlessAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                access_token: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GocardlessPaymentStatus {
    PendingCustomerApproval,
    PendingSubmission,
    Submitted,
    Confirmed,
    PaidOut,
    Cancelled,
    CustomerApprovalDenied,
    Failed,
}

impl From<GocardlessPaymentStatus> for enums::AttemptStatus {
    fn from(item: GocardlessPaymentStatus) -> Self {
        match item {
            GocardlessPaymentStatus::PendingCustomerApproval
            | GocardlessPaymentStatus::PendingSubmission
            | GocardlessPaymentStatus::Submitted => Self::Pending,
            GocardlessPaymentStatus::Confirmed | GocardlessPaymentStatus::PaidOut => Self::Charged,
            GocardlessPaymentStatus::Cancelled => Self::Voided,
            GocardlessPaymentStatus::CustomerApprovalDenied => Self::AuthenticationFailed,
            GocardlessPaymentStatus::Failed => Self::Failure,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GocardlessPaymentsResponse {
    payments: PaymentResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponse {
    status: GocardlessPaymentStatus,
    id: String,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            F,
            GocardlessPaymentsResponse,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    > for RouterData<F, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            F,
            GocardlessPaymentsResponse,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let mandate_reference = MandateReference {
            connector_mandate_id: Some(item.data.request.get_connector_mandate_id()?),
            payment_method_id: None,
            mandate_metadata: None,
            connector_mandate_request_reference_id: None,
        };
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.payments.status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payments.id),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(Some(mandate_reference)),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

impl<F>
    TryFrom<
        ResponseRouterData<F, GocardlessPaymentsResponse, PaymentsSyncData, PaymentsResponseData>,
    > for RouterData<F, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            F,
            GocardlessPaymentsResponse,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.payments.status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payments.id),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// REFUND :
#[derive(Default, Debug, Serialize)]
pub struct GocardlessRefundRequest {
    refunds: GocardlessRefund,
}

#[derive(Default, Debug, Serialize)]
pub struct GocardlessRefund {
    amount: i64,
    metadata: RefundMetaData,
    links: RefundLink,
}

#[derive(Default, Debug, Serialize)]
pub struct RefundMetaData {
    refund_reference: String,
}

#[derive(Default, Debug, Serialize)]
pub struct RefundLink {
    payment: String,
}

impl<F> TryFrom<&GocardlessRouterData<&types::RefundsRouterData<F>>> for GocardlessRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &GocardlessRouterData<&types::RefundsRouterData<F>>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            refunds: GocardlessRefund {
                amount: item.amount.to_owned(),
                metadata: RefundMetaData {
                    refund_reference: item.router_data.connector_request_reference_id.clone(),
                },
                links: RefundLink {
                    payment: item.router_data.request.connector_transaction_id.clone(),
                },
            },
        })
    }
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct RefundResponse {
    id: String,
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>>
    for types::RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::Pending,
            }),
            ..item.data
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GocardlessErrorResponse {
    pub error: GocardlessError,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GocardlessError {
    pub message: String,
    pub code: u16,
    pub errors: Vec<Error>,
    #[serde(rename = "type")]
    pub error_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Error {
    pub field: Option<String>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct GocardlessWebhookEvent {
    pub events: Vec<WebhookEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub resource_type: WebhookResourceType,
    pub action: WebhookAction,
    pub links: WebhooksLink,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookResourceType {
    Payments,
    Refunds,
    Mandates,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebhookAction {
    PaymentsAction(PaymentsAction),
    RefundsAction(RefundsAction),
    MandatesAction(MandatesAction),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentsAction {
    Created,
    CustomerApprovalGranted,
    CustomerApprovalDenied,
    Submitted,
    Confirmed,
    PaidOut,
    LateFailureSettled,
    SurchargeFeeDebited,
    Failed,
    Cancelled,
    ResubmissionRequired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundsAction {
    Created,
    Failed,
    Paid,
    // Payout statuses
    RefundSettled,
    FundsReturned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandatesAction {
    Created,
    CustomerApprovalGranted,
    CustomerApprovalSkipped,
    Active,
    Cancelled,
    Failed,
    Transferred,
    Expired,
    Submitted,
    ResubmissionRequested,
    Reinstated,
    Replaced,
    Consumed,
    Blocked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebhooksLink {
    PaymentWebhooksLink(PaymentWebhooksLink),
    RefundWebhookLink(RefundWebhookLink),
    MandateWebhookLink(MandateWebhookLink),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefundWebhookLink {
    pub refund: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentWebhooksLink {
    pub payment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MandateWebhookLink {
    pub mandate: String,
}

impl TryFrom<&WebhookEvent> for GocardlessPaymentsResponse {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &WebhookEvent) -> Result<Self, Self::Error> {
        let id = match &item.links {
            WebhooksLink::PaymentWebhooksLink(link) => link.payment.to_owned(),
            WebhooksLink::RefundWebhookLink(_) | WebhooksLink::MandateWebhookLink(_) => {
                Err(errors::ConnectorError::WebhookEventTypeNotFound)?
            }
        };
        Ok(Self {
            payments: PaymentResponse {
                status: GocardlessPaymentStatus::try_from(&item.action)?,
                id,
            },
        })
    }
}

impl TryFrom<&WebhookAction> for GocardlessPaymentStatus {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &WebhookAction) -> Result<Self, Self::Error> {
        match item {
            WebhookAction::PaymentsAction(action) => match action {
                PaymentsAction::CustomerApprovalGranted | PaymentsAction::Submitted => {
                    Ok(Self::Submitted)
                }
                PaymentsAction::CustomerApprovalDenied => Ok(Self::CustomerApprovalDenied),
                PaymentsAction::LateFailureSettled => Ok(Self::Failed),
                PaymentsAction::Failed => Ok(Self::Failed),
                PaymentsAction::Cancelled => Ok(Self::Cancelled),
                PaymentsAction::Confirmed => Ok(Self::Confirmed),
                PaymentsAction::PaidOut => Ok(Self::PaidOut),
                PaymentsAction::SurchargeFeeDebited
                | PaymentsAction::ResubmissionRequired
                | PaymentsAction::Created => Err(errors::ConnectorError::WebhookEventTypeNotFound)?,
            },
            WebhookAction::RefundsAction(_) | WebhookAction::MandatesAction(_) => {
                Err(errors::ConnectorError::WebhookEventTypeNotFound)?
            }
        }
    }
}
