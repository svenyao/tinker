//
// Created by sven on 6/1/17.
//

#include "sqlite_engine.h"
#include "logging.h"
#include "lexical_cast.h"

#include "sqlite3.h"

using namespace scom;

// tinker::sqlite operate
namespace tinker{
namespace sqlite{
//
// class DBConnect impl
//
DBConnect::DBConnect() : db_handle_(nullptr),db_key_(""){
}
DBConnect::~DBConnect(){
  DisConnect();
}
// connect db file.
int DBConnect::Connect(const std::string& db_path, const std::string& db_key){
  // open database
  int ret_code = sqlite3_open(db_path.c_str(), &db_handle_);
  if(ret_code != SQLITE_OK){
    LOG(error, "open database failed. error message:{}", sqlite3_errmsg(db_handle_));
    return -1;
  }

  if(!db_key.empty()){
    db_key_ = db_key;
    // todo: set key
#ifdef SQLITE_HAS_CODEC
    ret_code = sqlite3_key(db_handle_, db_key.c_str(), db_key.length());
    if(ret_code != SQLITE_OK){
      LOG(error, "open database key error. error message:{}", sqlite3_errmsg(db_handle_));
      return -1;
    }
#endif
  }

  return 0;
}
// reset db file encode key.
int DBConnect::ResetKey(const std::string& new_key, const std::string& old_key){
#ifdef SQLITE_HAS_CODEC
  if(!db_handle_) return -1;
  if(old_key == db_key_){
    int ret_code = sqlite3_rekey(db_handle_, new_key.c_str(), new_key.length());
    if(ret_code != SQLITE_OK){
      LOG(error, "open database key error. error message:{}", sqlite3_errmsg(db_handle_));
      return -1;
    }
  }
#endif
  return 0;
}

sqlite3* DBConnect::DBHandle(){
  return db_handle_;
}
// disconnect for db file.
void DBConnect::DisConnect(){
  if(db_handle_){
    int ret_code = sqlite3_close(db_handle_);
    if(ret_code != SQLITE_OK){
      LOG(error, "database close failed. error message:{}", sqlite3_errmsg(db_handle_));
    }
  }
}

//
// class DBCommand impl
//
DBCommand::DBCommand(DBConnectPtr db_connect) : db_connect_ptr_(db_connect){

}
DBCommand::~DBCommand(){

}

int DBCommand::Update(const std::string& sql_str){
  DBResultSetPtr result_set_ptr = Query(sql_str);
  if(!result_set_ptr) return -1;
  return 0;
}

DBResultSetPtr DBCommand::Query(const std::string& sql_str){
  if(!db_connect_ptr_->DBHandle()){
    LOG(error, "database had not open.");
    return nullptr;
  }
  DBResultSetPtr result_set_ptr = std::make_shared<DBResultSet>();

  char* error_msg;
  int ret_code = sqlite3_exec(db_connect_ptr_->DBHandle(), sql_str.c_str(),
                              DBCommand::callback, (void*)result_set_ptr.get(), &error_msg);
  if(ret_code != SQLITE_OK){
    LOG(error, "sqlite exec sql failed. error message:{}, sql:{}", error_msg, sql_str);
    sqlite3_free(error_msg);
    return nullptr;
  }
  return result_set_ptr;
}
int DBCommand::Execute(const std::string& sql_str, std::vector<DBResultSetPtr>& result_set_arr){
  if(!db_connect_ptr_->DBHandle()){
    LOG(error, "database had not open.");
    return -1;
  }
  char* error_msg;
  int ret_code = sqlite3_exec(db_connect_ptr_->DBHandle(), sql_str.c_str(),
                              DBCommand::callback2, (void*)&result_set_arr, &error_msg);
  if(ret_code != SQLITE_OK){
    LOG(error, "sqlite exec sql failed. error message:{}, sql:{}", error_msg, sql_str);
    sqlite3_free(error_msg);
    return -1;
  }
  return 0;
}

int DBCommand::callback(void* data, int argc, char** argv, char** szColName){
  DBResultSet* result_set_pt = (DBResultSet*)data;
  return result_set_pt->Initialize(argc, argv, szColName);
}
int DBCommand::callback2(void* data, int argc, char** argv, char** szColName){
  std::vector<DBResultSetPtr>* result_set_arr = (std::vector<DBResultSetPtr>*)data;
  DBResultSetPtr result_set_ptr = std::make_shared<DBResultSet>();
  result_set_ptr->Initialize(argc, argv, szColName);
  result_set_arr->push_back(result_set_ptr);
  return 0;
}

//
// class DBResultSet impl
//
DBResultSet::DBResultSet() : fetch_idx_(0){

}
DBResultSet::~DBResultSet(){
  // clear all object.
  for(auto iter : result_set_v_){
    iter.clear();
  }
  result_set_v_.clear();
  column_label_m_.clear();
}

// Initialize
int DBResultSet::Initialize(int argc, char** argv, char** column_name){
  bool update_column_able = false;
  if(column_label_m_.empty()) update_column_able = true;
  std::unordered_map<std::string, std::string> result_set;
  for(unsigned int idx = 0; idx < (unsigned int)argc; ++idx){
    // update column value
    result_set.insert(std::make_pair(column_name[idx], argv[idx]));
    // update column label.
    if(update_column_able) {
      column_label_m_.insert(std::make_pair(idx, column_name[idx]));
    }
  }
  result_set_v_.push_back(result_set);
  return 0;
}

// if had next row return true, else return false.
bool DBResultSet::FetchNext(){
  if(fetch_idx_ < result_set_v_.size()){
    ++fetch_idx_;
    return true;
  }
  return false;
}
// get operate
std::istream * DBResultSet::GetBlob(const std::string& column_label) const{
  std::stringstream* oss = new std::stringstream;
  *oss << GetString(column_label);
  return oss;
}
long double DBResultSet::GetDouble(const std::string& column_label) const{
  return lexical_cast<double>(GetString(column_label));
}
bool DBResultSet::GetBoolean(const std::string& column_label) const{
  return lexical_cast<bool>(GetString(column_label));
}
int32_t DBResultSet::GetInt(const std::string& column_label) const{
  return lexical_cast<int32_t>(GetString(column_label));
}
uint32_t DBResultSet::GetUInt(const std::string& column_label) const{
  return lexical_cast<uint32_t>(GetString(column_label));
}
int64_t DBResultSet::GetInt64(const std::string& column_label) const{
  return lexical_cast<int64_t>(GetString(column_label));
}
uint64_t DBResultSet::GetUInt64(const std::string& column_label) const{
  return lexical_cast<uint64_t>(GetString(column_label));
}
std::string DBResultSet::GetString(const std::string& column_label) const{
  if(fetch_idx_ == 0 || fetch_idx_ > result_set_v_.size()){
    return std::move(std::string());
  }
  auto result_set = result_set_v_.at(fetch_idx_-1);
  auto iter = result_set.find(column_label);
  if(iter != result_set.end()){
    return iter->second;
  }
  return std::move(std::string());
}

}//namespace sqlite
}//!namespace thinker