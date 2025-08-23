use common_enums::enums;
use common_utils::{request::Method, types::StringMinorUnit};
use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::{RefundsData, ResponseId},
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors::{self, ConnectorError};
use masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{types::ResponseRouterData, utils::PaymentsAuthorizeRequestData};

// Router Data
pub struct BkashRouterData<T> {
    pub amount: StringMinorUnit,
    pub router_data: T,
}

impl<T> From<(StringMinorUnit, T)> for BkashRouterData<T> {
    fn from((amount, item): (StringMinorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

// Authentication
pub struct BkashAuthType {
    pub(super) app_key: Secret<String>,
    pub(super) app_secret: Secret<String>,
    pub(super) username: Secret<String>,
    pub(super) password: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BkashAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                app_key: api_key.to_owned(),
                app_secret: key1.to_owned(),
                username: api_secret.to_owned(),
                password: key2.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Access Token
#[derive(Debug, Serialize)]
pub struct BkashAccessTokenRequest {
    pub app_key: Secret<String>,
    pub app_secret: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BkashAccessTokenResponse {
    pub id_token: Secret<String>,
    pub expires: i64,
}

impl<F, T> TryFrom<ResponseRouterData<F, BkashAccessTokenResponse, T, AccessToken>>
    for RouterData<F, T, AccessToken>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, BkashAccessTokenResponse, T, AccessToken>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(AccessToken {
                token: item.response.id_token,
                expires: item.response.expires,
            }),
            ..item.data
        })
    }
}

// Payments
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BkashPaymentsRequest {
    mode: String,
    payer_reference: String,
    callback_url: String,
    amount: StringMinorUnit,
    currency: String,
    intent: String,
    merchant_invoice_number: String,
}

impl TryFrom<&BkashRouterData<&PaymentsAuthorizeRouterData>> for BkashPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &BkashRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        let intent = if item.router_data.request.is_auto_capture()? {
            "sale".to_string()
        } else {
            "authorization".to_string()
        };

        let callback_url = item.router_data.request.get_router_return_url()?;

        Ok(Self {
            mode: "0011".to_string(),
            payer_reference: "00".to_string(),
            callback_url,
            amount: item.amount.clone(),
            currency: "BDT".to_string(),
            intent,
            merchant_invoice_number: item.router_data.connector_request_reference_id.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum BkashPaymentStatus {
    Initiated,
    Completed,
    Failed,
    Cancelled,
}

impl From<BkashPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BkashPaymentStatus) -> Self {
        match item {
            BkashPaymentStatus::Initiated => Self::AuthenticationPending,
            BkashPaymentStatus::Completed => Self::Charged,
            BkashPaymentStatus::Failed => Self::Failure,
            BkashPaymentStatus::Cancelled => Self::Voided,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BkashPaymentsResponse {
    payment_id: String,
    transaction_status: BkashPaymentStatus,
    bkash_url: String,
}

impl<F, T> TryFrom<ResponseRouterData<F, BkashPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, BkashPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let redirection_data = Some(RedirectForm::Form {
            endpoint: item.response.bkash_url.clone(),
            method: Method::Get,
            form_fields: std::collections::HashMap::new(),
        });

        Ok(Self {
            status: common_enums::AttemptStatus::from(item.response.transaction_status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id.clone()),
                redirection_data: Box::new(redirection_data),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.payment_id),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// Refunds
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BkashRefundRequest {
    pub payment_id: String,
    pub amount: StringMinorUnit,
    pub sku: String,
    pub reason: String,
}

impl<F> TryFrom<&BkashRouterData<&RefundsRouterData<F>>> for BkashRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &BkashRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            payment_id: item.router_data.request.connector_transaction_id.clone(),
            amount: item.amount.clone(),
            sku: item
                .router_data
                .request
                .reason
                .clone()
                .unwrap_or("Refund".to_string()),
            reason: item
                .router_data
                .request
                .reason
                .clone()
                .unwrap_or("Refund".to_string()),
        })
    }
}

#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum RefundStatus {
    Completed,
    #[default]
    Processing,
    Failed,
}

impl From<RefundStatus> for common_enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Completed => Self::Success,
            RefundStatus::Processing => Self::Pending,
            RefundStatus::Failed => Self::Failure,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundResponse {
    pub trx_id: String,
    pub transaction_status: RefundStatus,
}
impl TryFrom<ResponseRouterData<Execute, RefundResponse, RefundsData, RefundsResponseData>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<Execute, RefundResponse, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.trx_id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.transaction_status),
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BkashCaptureRequest {
    payment_id: String,
    amount: StringMinorUnit,
}

impl TryFrom<&BkashRouterData<&PaymentsCaptureRouterData>> for BkashCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &BkashRouterData<&PaymentsCaptureRouterData>) -> Result<Self, Self::Error> {
        Ok(Self {
            payment_id: item.router_data.request.connector_transaction_id.clone(),
            amount: item.amount.clone(),
        })
    }
}

impl TryFrom<ResponseRouterData<RSync, RefundResponse, RefundsData, RefundsResponseData>>
    for RefundsRouterData<RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RSync, RefundResponse, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.trx_id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.transaction_status),
            }),
            ..item.data
        })
    }
}

// Errors
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BkashErrorResponse {
    pub status_code: u16,
    pub error_code: String,
    pub error_message: String,
    pub reason: Option<String>,
    pub network_advice_code: Option<String>,
    pub network_decline_code: Option<String>,
    pub network_error_message: Option<String>,
}
