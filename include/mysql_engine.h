//
// Created by sven on 6/1/17.
//

#ifndef TINKER_MYSQL_ENGINE_H
#define TINKER_MYSQL_ENGINE_H
#include "tinker_config.h"
#include <stdint.h>
#include <string>
#include <vector>
#include <memory>

namespace sql {
  class Connection;
  class Statement;
  class ResultSet;
}// namespace sql

//
// tinker::mysql guide for use.
// tinker::mysql::DBConnectPtr db_connect = std::make_shared<tinker::mysql::DBConnect>();
// if(db_connect->Connect("127.0.0.1:3306", "name", "passwd", "db_name") != 0) return -1;
// tinker::mysql::DBCommandPtr db_command = std::make_shared<tinker::mysql::DBCommand>(db_connect);
// if(!db_command) return -1;
// tinker::mysql::DBResultSetPtr result = db_command->Query("select cid from table");
// while(result && result->FetchNext()){
//   std::string str = result->GetString("cid");
// }
//
namespace tinker{
namespace mysql{

class DBCommand;
class TINKER_API DBConnect{
  public:
  explicit DBConnect(bool auto_commit = true);
  virtual ~DBConnect();
  int Connect(std::string url, std::string username, std::string passwd, std::string schema);

  int KeepAlive(); // default query dual. reconnected.

  void Commit();
  void Rollback();
  void SetAutoCommit(bool auto_commit);

  protected:
  friend class DBCommand;
  sql::Statement* Statement();
  private:
  std::string url_;
  std::string username_;
  std::string passwd_;
  std::string schema_;
  bool auto_commit_;
  sql::Connection *connect_pt_;
  sql::Statement *stmt_pt_;
};
typedef std::shared_ptr<DBConnect> DBConnectPtr;

class DBResultSet;
typedef std::shared_ptr<DBResultSet> DBResultSetPtr;

class TINKER_API DBCommand{
  public:
  explicit DBCommand(DBConnectPtr db_connect_ptr);
  virtual ~DBCommand();

  // execute update or insert command and return the number of rows affected.
  int Update(const std::string& sql_str);
  // execute select command and return one ResultSet.
  DBResultSetPtr Query(const std::string& sql_str);
  // execute all command (procedure).
  int Execute(const std::string& sql_str, std::vector<DBResultSetPtr>& db_result_arr);
  private:
  DBConnectPtr db_connect_ptr_;
};
typedef std::shared_ptr<DBCommand> DBCommandPtr;

class TINKER_API DBResultSet{
  public:
  explicit DBResultSet(std::shared_ptr<sql::ResultSet> result);
  virtual ~DBResultSet();

  // if had next row return true, else return false.
  bool FetchNext();
  // get operate
  std::istream * GetBlob(const std::string& column_label) const;
  long double GetDouble(const std::string& column_label) const;
  bool GetBoolean(const std::string& column_label) const;
  int32_t GetInt(const std::string& column_label) const;
  uint32_t GetUInt(const std::string& column_label) const;
  int64_t GetInt64(const std::string& column_label) const;
  uint64_t GetUInt64(const std::string& column_label) const;
  std::string GetString(const std::string& column_label) const;

  //sql::ResultSet* ResultSet();
  private:
  std::shared_ptr<sql::ResultSet> result_pt_;
};

}//!namespace mysql
}//!namespace tinker

#endif //TINKER_MYSQL_ENGINE_H
