//
// Created by sven on 6/1/17.
//

#ifndef TINKER_SQLITE_ENGINE_H
#define TINKER_SQLITE_ENGINE_H
#include "tinker_config.h"
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

struct sqlite3;

//
// tinker::sqlite guide for use.
// tinker::sqlite::DBConnectPtr db_connect = std::make_shared<tinker::sqlite::DBConnect>();
// if(db_connect->Connect("test.db", "key") != 0) return -1;
// tinker::sqlite::DBCommandPtr db_command = std::make_shared<tinker::sqlite::DBCommand>(db_connect);
// if(!db_command) return -1;
// tinker::sqlite::DBResultSetPtr result = db_command->Query("select cid from table");
// while(result && result->FetchNext()){
//   std::string str = result->GetString("cid");
// }
//
namespace tinker{
namespace sqlite{

class DBCommand;
class TINKER_API DBConnect{
  public:
  DBConnect();
  virtual ~DBConnect();
  // connect db file.
  int Connect(const std::string& db_path, const std::string& db_key = "");
  // reset db file encode key.
  int ResetKey(const std::string& new_key, const std::string& old_key);
  protected:
  friend class DBCommand;
  sqlite3* DBHandle();
  // disconnect for db file.
  void DisConnect();
  private:
  sqlite3* db_handle_;
  std::string db_key_;
};
typedef std::shared_ptr<DBConnect> DBConnectPtr;

class DBResultSet;
typedef std::shared_ptr<DBResultSet> DBResultSetPtr;

class TINKER_API DBCommand{
  public:
  explicit DBCommand(DBConnectPtr db_connect);
  virtual ~DBCommand();

  int Update(const std::string& sql_str);
  DBResultSetPtr Query(const std::string& sql_str);
  int Execute(const std::string& sql_str, std::vector<DBResultSetPtr>& result_set_arr);

  protected:
  static int callback(void* data, int argc, char** argv, char** szColName);
  static int callback2(void* data, int argc, char** argv, char** szColName);
  private:
  DBConnectPtr db_connect_ptr_;
};
typedef std::shared_ptr<DBCommand> DBCommandPtr;

class TINKER_API DBResultSet{
  public:
  DBResultSet();
  virtual ~DBResultSet();
  // Initialize
  int Initialize(int argc, char** argv, char** column_name);

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

  private:
  std::vector<std::unordered_map<std::string, std::string>> result_set_v_;
  std::unordered_map<uint32_t, std::string> column_label_m_; // <column id, column label>
  uint32_t fetch_idx_;
};

}//!namespace sqlite
}//!namespace tinker

#endif //TINKER_SQLITE_ENGINE_H
