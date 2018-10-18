//
// Created by sven on 6/1/17.
//

#include "mysql_engine.h"
#include "logging.h"

#include "cppconn/driver.h"
#include "cppconn/resultset.h"
#include "cppconn/statement.h"

// tinker::mysql operate
namespace tinker{
namespace mysql{
//
// class DBConnect impl.
//
DBConnect::DBConnect(bool auto_commit) :
    auto_commit_(auto_commit),
    connect_pt_(nullptr), stmt_pt_(nullptr){
}
DBConnect::~DBConnect(){
  if(connect_pt_){
    delete connect_pt_; connect_pt_ = nullptr;
  }
  if(stmt_pt_){
    delete stmt_pt_; stmt_pt_ = nullptr;
  }
}

int DBConnect::Connect(std::string url, std::string username, std::string passwd, std::string schema){
  url_ = url;
  username_ = username;
  passwd_ = passwd;
  schema_ = schema;
  if(connect_pt_) return 0;
  try
  {
    sql::Driver* driver = get_driver_instance();
    if (driver == nullptr){
      LOG(error, "[mysql] get_driver_instance() error.");
      return -1;
    }
    sql::ConnectOptionsMap options;
    options["hostName"] = sql::SQLString(url_);
    options["userName"] = sql::SQLString(username);
    options["password"] = sql::SQLString(passwd);
    if (!schema.empty())
      options["schema"] = sql::SQLString(schema);
    options["OPT_RECONNECT"] = true;
    options["CLIENT_FOUND_ROWS"] = true;
    // set timeout integer
    //options["OPT_READ_TIMEOUT"] = 5;
    //options["OPT_WRITE_TIMEOUT"] = 5;
    connect_pt_ = driver->connect(options);
    if (connect_pt_ == nullptr) {
      LOG(error, "datebase connect failed. ");
      return -1;
    }
    // turn on/off the autocommit
    connect_pt_->setAutoCommit(auto_commit_);
    //VLOG(0) << "connection/'s autocommit mode = " << conn->getAutoCommit() << std::endl;
    // select appropriate database schema
    connect_pt_->setSchema(schema);

    stmt_pt_ = connect_pt_->createStatement();
    return 0;
  }
  catch(sql::SQLException &e){
    LOG(error, "ERROR: {}", e.what());
    LOG(error, "(MySQL error code: {}, SQLState: {}", e.getErrorCode(), e.getSQLState());
  }
  catch (std::runtime_error &e) {
    LOG(error, "ERROR: {}", e.what());
  }
  return -1;
}

void DBConnect::Commit()
{
  connect_pt_->commit();
}

void DBConnect::Rollback()
{
  connect_pt_->rollback();
}
void DBConnect::SetAutoCommit(bool auto_commit){
  auto_commit_ = auto_commit;
  connect_pt_->setAutoCommit(auto_commit_);
}

sql::Statement* DBConnect::Statement(){
  return stmt_pt_;
}

int DBConnect::KeepAlive() {
  std::string sql_str = "select 0 from dual";
  try {
    if (stmt_pt_ == nullptr){
      return -1;
    }
    // execute query
    std::shared_ptr<sql::ResultSet> result(stmt_pt_->executeQuery(sql_str));

    while (result && result->next()){
      LOG(debug, "KeepAlive connected success. > {} ", sql_str);
    }
    if(!result){
      LOG(debug, "KeepAlive connected failed. sleep 2 second. > {}", sql_str);
      std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    else {
      return 0;
    }
  }
  catch(sql::SQLException &e){
    LOG(error, "{}", sql_str);
    LOG(error, "ERROR: {}", e.what());
    LOG(error, "(MySQL error code: {}, SQLState: {}", e.getErrorCode(), e.getSQLState());
  }
  catch (std::runtime_error &e) {
    LOG(error, "ERROR: {}", e.what());
  }
//  KeepAlive();
  return -1;
}

//
// class DBCommand impl.
//
DBCommand::DBCommand(DBConnectPtr db_connect_ptr) : db_connect_ptr_(db_connect_ptr){
}

DBCommand::~DBCommand(){
}

int DBCommand::Update(const std::string& sql_str){
  try {
    if (!db_connect_ptr_ || !db_connect_ptr_->Statement()) {
      return -1;
    }
    // execute query
    int row_count = db_connect_ptr_->Statement()->executeUpdate(sql_str);
    return row_count;
  }
  catch(sql::SQLException &e) {
    LOG(error, "{}", sql_str);
    LOG(error, "ERROR: {}", e.what());
    LOG(error, "(MySQL error code: {}, SQLState: {}", e.getErrorCode(), e.getSQLState());
  }
  catch (std::runtime_error &e) {
    LOG(error, "ERROR: {}", e.what());
  }
  return -1;
}

DBResultSetPtr DBCommand::Query(const std::string& sql_str){
  try {
    if (!db_connect_ptr_ || !db_connect_ptr_->Statement()) {
      return nullptr;
    }
    // execute query
    std::shared_ptr<sql::ResultSet> result_ptr(db_connect_ptr_->Statement()->executeQuery(sql_str));
    return std::make_shared<DBResultSet>(result_ptr);
  }
  catch(sql::SQLException &e) {
    LOG(error, "{}", sql_str);
    LOG(error, "ERROR: {}", e.what());
    LOG(error, "(MySQL error code: {}, SQLState: {}", e.getErrorCode(), e.getSQLState());
  }
  catch (std::runtime_error &e) {
    LOG(error, "ERROR: {}", e.what());
  }
  return nullptr;
}

int DBCommand::Execute(const std::string& sql_str, std::vector<DBResultSetPtr>& db_result_arr){
  try {
    if (!db_connect_ptr_ || !db_connect_ptr_->Statement()) {
      return -1;
    }
    // execute query
    bool bval = db_connect_ptr_->Statement()->execute(sql_str);
    if(bval){
      do {
        std::shared_ptr<sql::ResultSet> result_ptr(db_connect_ptr_->Statement()->getResultSet());
        db_result_arr.push_back(std::make_shared<DBResultSet>(result_ptr));
      } while (db_connect_ptr_->Statement()->getMoreResults());
      return 0;
    }
    else{
      return static_cast<int>(db_connect_ptr_->Statement()->getUpdateCount());
    }
  }
  catch(sql::SQLException &e) {
    LOG(error, "{}", sql_str);
    LOG(error, "ERROR: {}", e.what());
    LOG(error, "(MySQL error code: {}, SQLState: {}", e.getErrorCode(), e.getSQLState());
  }
  catch (std::runtime_error &e) {
    LOG(error, "ERROR: {}", e.what());
  }
  return -1;
}

//
// class DBResultSet impl.
//
DBResultSet::DBResultSet(std::shared_ptr<sql::ResultSet> result)
    : result_pt_(result){
}
DBResultSet::~DBResultSet(){

}

// if had next row return true, else return false.
bool DBResultSet::FetchNext(){
  try {
    return (result_pt_ && result_pt_->next());
  }
  catch(sql::SQLException &e) {
    LOG(error, "ERROR: {}", e.what());
    LOG(error, "(MySQL error code: {}, SQLState: {}", e.getErrorCode(), e.getSQLState());
  }
  catch (std::runtime_error &e) {
    LOG(error, "ERROR: {}", e.what());
  }
  return nullptr;
}
// get operate
std::istream* DBResultSet::GetBlob(const std::string& column_label) const{
  try {
    return result_pt_->getBlob(column_label);
  }
  catch (sql::SQLException &e) {
    LOG(error, "[ERROR]: {}, Label:[{}]", e.what(), column_label);
  }
  return nullptr;
}

long double DBResultSet::GetDouble(const std::string& column_label) const{
  try {
    return result_pt_->getDouble(column_label);
  }
  catch (sql::SQLException &e) {
    LOG(error, "[ERROR]: {}, Label:[{}]", e.what(), column_label);
  }
  return 0;
}

bool DBResultSet::GetBoolean(const std::string& column_label) const{
  try {
    return result_pt_->getBoolean(column_label);
  }
  catch (sql::SQLException &e) {
    LOG(error, "[ERROR]: {}, Label:[{}]", e.what(), column_label);
  }
  return false;
}

int32_t DBResultSet::GetInt(const std::string& column_label) const{
  try {
    return result_pt_->getInt(column_label);
  }
  catch (sql::SQLException &e) {
    LOG(error, "[ERROR]: {}, Label:[{}]", e.what(), column_label);
  }
  return 0;
}

uint32_t DBResultSet::GetUInt(const std::string& column_label) const{
  try {
    return result_pt_->getUInt(column_label);
  }
  catch (sql::SQLException &e) {
    LOG(error, "[ERROR]: {}, Label:[{}]", e.what(), column_label);
  }
  return 0;
}

int64_t DBResultSet::GetInt64(const std::string& column_label) const{
  try {
    return result_pt_->getInt64(column_label);
  }
  catch (sql::SQLException &e) {
    LOG(error, "[ERROR]: {}, Label:[{}]", e.what(), column_label);
  }
  return 0;
}

uint64_t DBResultSet::GetUInt64(const std::string& column_label) const{
  try {
    return result_pt_->getUInt64(column_label);
  }
  catch (sql::SQLException &e) {
    LOG(error, "[ERROR]: {}, Label:[{}]", e.what(), column_label);
  }
  return 0;
}

std::string DBResultSet::GetString(const std::string& column_label) const{
  try {
    return result_pt_->getString(column_label);
  }
  catch (sql::SQLException &e) {
    LOG(error, "[ERROR]: {}, Label:[{}]", e.what(), column_label);
  }
  return std::string();
}

}//!namespace mysql
}//!namespace thinker
