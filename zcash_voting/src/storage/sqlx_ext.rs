//! Small dynamic-query helpers used while keeping SQL out of macros.
//!
//! SQLx only accepts positional SQLite parameters at runtime. The voting
//! schema historically used named parameters, so this module rewrites those
//! names to SQLx's numbered `?NNN` form and owns the bound values until the
//! async query completes.

use std::collections::HashMap;

use sqlx::{
    sqlite::{SqliteQueryResult, SqliteRow},
    ColumnIndex, Decode, Row as _, Sqlite, SqliteConnection, Type,
};

#[derive(Clone, Debug)]
pub enum SqlValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

pub trait IntoSqlValue {
    fn into_sql_value(self) -> SqlValue;
}

impl IntoSqlValue for SqlValue {
    fn into_sql_value(self) -> SqlValue {
        self
    }
}

impl IntoSqlValue for &str {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Text(self.to_owned())
    }
}

impl IntoSqlValue for String {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Text(self)
    }
}

impl IntoSqlValue for &String {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Text(self.clone())
    }
}

impl IntoSqlValue for &[u8] {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Blob(self.to_vec())
    }
}

impl<const N: usize> IntoSqlValue for &[u8; N] {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Blob(self.to_vec())
    }
}

impl<const N: usize> IntoSqlValue for [u8; N] {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Blob(self.to_vec())
    }
}

impl IntoSqlValue for Vec<u8> {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Blob(self)
    }
}

impl IntoSqlValue for &Vec<u8> {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Blob(self.clone())
    }
}

macro_rules! integer_values {
    ($($ty:ty),* $(,)?) => {
        $(
            impl IntoSqlValue for $ty {
                fn into_sql_value(self) -> SqlValue {
                    SqlValue::Integer(self as i64)
                }
            }

            impl IntoSqlValue for &$ty {
                fn into_sql_value(self) -> SqlValue {
                    SqlValue::Integer(*self as i64)
                }
            }
        )*
    };
}

integer_values!(i8, i16, i32, i64, u8, u16, u32, u64, usize);

impl IntoSqlValue for f64 {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Real(self)
    }
}

impl IntoSqlValue for bool {
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Integer(i64::from(self))
    }
}

impl<T> IntoSqlValue for Option<T>
where
    T: IntoSqlValue,
{
    fn into_sql_value(self) -> SqlValue {
        self.map(IntoSqlValue::into_sql_value)
            .unwrap_or(SqlValue::Null)
    }
}

impl<T> IntoSqlValue for &Option<T>
where
    for<'a> &'a T: IntoSqlValue,
{
    fn into_sql_value(self) -> SqlValue {
        self.as_ref()
            .map(IntoSqlValue::into_sql_value)
            .unwrap_or(SqlValue::Null)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Params {
    named: Vec<(&'static str, SqlValue)>,
    positional: Vec<SqlValue>,
}

impl Params {
    pub fn named(values: Vec<(&'static str, SqlValue)>) -> Self {
        Self {
            named: values,
            positional: vec![],
        }
    }

    pub fn positional(values: Vec<SqlValue>) -> Self {
        Self {
            named: vec![],
            positional: values,
        }
    }
}

impl<const N: usize> From<[(); N]> for Params {
    fn from(_: [(); N]) -> Self {
        Self::default()
    }
}

#[macro_export]
macro_rules! named_params {
    ($($name:literal : $value:expr),* $(,)?) => {
        $crate::storage::sqlx_ext::Params::named(vec![
            $(($name, $crate::storage::sqlx_ext::IntoSqlValue::into_sql_value($value))),*
        ])
    };
}

#[macro_export]
macro_rules! params {
    ($($value:expr),* $(,)?) => {
        $crate::storage::sqlx_ext::Params::positional(vec![
            $($crate::storage::sqlx_ext::IntoSqlValue::into_sql_value($value)),*
        ])
    };
}

fn numbered_sql(sql: &str, params: &Params) -> Result<String, sqlx::Error> {
    if params.named.is_empty() {
        return Ok(sql.to_owned());
    }

    let indices: HashMap<&str, usize> = params
        .named
        .iter()
        .enumerate()
        .map(|(index, (name, _))| (*name, index + 1))
        .collect();
    let bytes = sql.as_bytes();
    let mut output = String::with_capacity(sql.len());
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes[cursor] == b':' {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            let name = &sql[start..cursor];
            let index = indices
                .get(name)
                .ok_or_else(|| sqlx::Error::Protocol(format!("missing SQL parameter {name}")))?;
            output.push('?');
            output.push_str(&index.to_string());
        } else {
            let ch = sql[cursor..].chars().next().expect("valid UTF-8 boundary");
            output.push(ch);
            cursor += ch.len_utf8();
        }
    }

    Ok(output)
}

fn bind_values<'q>(
    mut query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    params: Params,
) -> sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    let values = if params.named.is_empty() {
        params.positional
    } else {
        params.named.into_iter().map(|(_, value)| value).collect()
    };
    for value in values {
        query = match value {
            SqlValue::Null => query.bind(Option::<i64>::None),
            SqlValue::Integer(value) => query.bind(value),
            SqlValue::Real(value) => query.bind(value),
            SqlValue::Text(value) => query.bind(value),
            SqlValue::Blob(value) => query.bind(value),
        };
    }
    query
}

pub async fn execute(
    conn: &mut SqliteConnection,
    sql: &str,
    params: Params,
) -> Result<usize, sqlx::Error> {
    let sql = numbered_sql(sql, &params)?;
    Ok(bind_values(sqlx::query(&sql), params)
        .execute(conn)
        .await?
        .rows_affected() as usize)
}

pub async fn query_row<T, F>(
    conn: &mut SqliteConnection,
    sql: &str,
    params: Params,
    map: F,
) -> Result<T, sqlx::Error>
where
    F: FnOnce(&SqlRow) -> Result<T, sqlx::Error>,
{
    let sql = numbered_sql(sql, &params)?;
    let row = bind_values(sqlx::query(&sql), params)
        .fetch_one(conn)
        .await?;
    map(&SqlRow(row))
}

pub async fn query_map<T, F>(
    conn: &mut SqliteConnection,
    sql: &str,
    params: Params,
    mut map: F,
) -> Result<Vec<T>, sqlx::Error>
where
    F: FnMut(&SqlRow) -> Result<T, sqlx::Error>,
{
    let sql = numbered_sql(sql, &params)?;
    let rows = bind_values(sqlx::query(&sql), params)
        .fetch_all(conn)
        .await?;
    rows.into_iter().map(|row| map(&SqlRow(row))).collect()
}

pub async fn execute_batch(conn: &mut SqliteConnection, sql: &str) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(sql).execute(conn).await?;
    Ok(())
}

/// Async methods mirroring the small subset of the old connection API used by
/// the voting query layer. Every method executes through SQLx.
pub trait ConnectionExt {
    fn prepare(&mut self, sql: &str) -> Result<Statement<'_>, sqlx::Error>;

    async fn execute<P>(&mut self, sql: &str, params: P) -> Result<usize, sqlx::Error>
    where
        P: Into<Params>;

    async fn query_row<T, P, F>(&mut self, sql: &str, params: P, map: F) -> Result<T, sqlx::Error>
    where
        P: Into<Params>,
        F: FnOnce(&SqlRow) -> Result<T, sqlx::Error>;

    async fn execute_batch(&mut self, sql: &str) -> Result<(), sqlx::Error>;
}

impl ConnectionExt for SqliteConnection {
    fn prepare(&mut self, sql: &str) -> Result<Statement<'_>, sqlx::Error> {
        Ok(Statement {
            conn: self,
            sql: sql.to_owned(),
        })
    }

    async fn execute<P>(&mut self, sql: &str, params: P) -> Result<usize, sqlx::Error>
    where
        P: Into<Params>,
    {
        execute(self, sql, params.into()).await
    }

    async fn query_row<T, P, F>(&mut self, sql: &str, params: P, map: F) -> Result<T, sqlx::Error>
    where
        P: Into<Params>,
        F: FnOnce(&SqlRow) -> Result<T, sqlx::Error>,
    {
        query_row(self, sql, params.into(), map).await
    }

    async fn execute_batch(&mut self, sql: &str) -> Result<(), sqlx::Error> {
        execute_batch(self, sql).await
    }
}

pub struct Statement<'c> {
    conn: &'c mut SqliteConnection,
    sql: String,
}

impl Statement<'_> {
    pub async fn query_map<T, P, F>(
        &mut self,
        params: P,
        map: F,
    ) -> Result<Vec<Result<T, sqlx::Error>>, sqlx::Error>
    where
        P: Into<Params>,
        F: FnMut(&SqlRow) -> Result<T, sqlx::Error>,
    {
        Ok(query_map(self.conn, &self.sql, params.into(), map)
            .await?
            .into_iter()
            .map(Ok)
            .collect())
    }
}

pub struct SqlRow(SqliteRow);

impl SqlRow {
    pub fn get<'r, I, T>(&'r self, index: I) -> Result<T, sqlx::Error>
    where
        I: ColumnIndex<SqliteRow>,
        T: Decode<'r, Sqlite> + Type<Sqlite>,
    {
        self.0.try_get(index)
    }
}

pub trait OptionalExtension<T> {
    fn optional(self) -> Result<Option<T>, sqlx::Error>;
}

impl<T> OptionalExtension<T> for Result<T, sqlx::Error> {
    fn optional(self) -> Result<Option<T>, sqlx::Error> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

pub type QueryResult = SqliteQueryResult;
