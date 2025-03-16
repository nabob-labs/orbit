use common_enums::{Owner, UserAuthType};
use diesel_models::UserAuthenticationMethod;
use once_cell::sync::Lazy;

pub static DEFAULT_USER_AUTH_METHOD: Lazy<UserAuthenticationMethod> =
    Lazy::new(|| UserAuthenticationMethod {
        id: String::from("orbit_default"),
        auth_id: String::from("orbit"),
        owner_id: String::from("orbit"),
        owner_type: Owner::Tenant,
        auth_type: UserAuthType::Password,
        private_config: None,
        public_config: None,
        allow_signup: true,
        created_at: common_utils::date_time::now(),
        last_modified_at: common_utils::date_time::now(),
        email_domain: String::from("orbit"),
    });
