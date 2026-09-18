//! Queries for the `oauth_authorization_codes` table.

use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, UpdateMany,
    sea_query::Expr,
};

use crate::{
    db::entities::oauth_authorization_codes::{Column, Entity as Codes},
    oauth::authorization::AuthorizationCode,
};

pub async fn insert(db: &impl ConnectionTrait, code: &AuthorizationCode) -> Result<(), DbErr> {
    Codes::insert(code.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

/// Builds the one statement that makes codes one-time.
///
/// ```sql
/// UPDATE oauth_authorization_codes SET used_at = $2
/// WHERE code_hash = $1 AND used_at IS NULL
/// ```
///
/// Separate from [`claim`] so the test below can assert on the SQL: the
/// `used_at IS NULL` condition is the security property, and a refactor that
/// dropped it would let a code be redeemed twice.
fn claim_statement(code_hash: &str, now: DateTime<Utc>) -> UpdateMany<Codes> {
    Codes::update_many()
        .col_expr(Column::UsedAt, Expr::value(now))
        .filter(Column::CodeHash.eq(code_hash))
        .filter(Column::UsedAt.is_null())
}

/// Atomically marks an unused code as used and returns it (`RETURNING *`).
///
/// If two requests race with the same code, PostgreSQL's row lock guarantees
/// only one of them gets a row back. Returns `None` if the code does not
/// exist *or* was already used.
///
/// Note that expiry is deliberately *not* checked here: an expired code is
/// still consumed so it can never be tried again.
pub async fn claim(
    db: &impl ConnectionTrait,
    code_hash: &str,
    now: DateTime<Utc>,
) -> Result<Option<AuthorizationCode>, DbErr> {
    let claimed = claim_statement(code_hash, now)
        .exec_with_returning(db)
        .await?;
    Ok(claimed.into_iter().next())
}

pub async fn find_by_hash(
    db: &impl ConnectionTrait,
    code_hash: &str,
) -> Result<Option<AuthorizationCode>, DbErr> {
    Codes::find()
        .filter(Column::CodeHash.eq(code_hash))
        .one(db)
        .await
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, QueryTrait};

    use super::*;

    #[test]
    fn claim_only_matches_a_code_that_was_never_used() {
        let sql = claim_statement("the-hash", Utc::now())
            .build(DbBackend::Postgres)
            .to_string();

        assert!(
            sql.starts_with(r#"UPDATE "oauth_authorization_codes" SET "used_at" ="#),
            "{sql}"
        );
        assert!(sql.contains(r#""code_hash" = 'the-hash'"#), "{sql}");
        assert!(
            sql.contains(r#""used_at" IS NULL"#),
            "one-time use depends on this: {sql}"
        );
    }
}
