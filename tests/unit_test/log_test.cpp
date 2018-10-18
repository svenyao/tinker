#include "mysql_engine.h"
#include "logging.h"

using namespace tinker;

int main(int argc, char** argv) {
  tinker::mysql::DBConnectPtr db_connect = std::make_shared<tinker::mysql::DBConnect>();
  if(db_connect->Connect("172.16.1.52:13306", "ison2", "ison2&lhhj", "ison20") == 0){
    LOG(info, "connect successfull.");
  }
  else{
    LOG(error, "connect failed.");
    return -1;
  }
  tinker::mysql::DBCommandPtr db_command = std::make_shared<tinker::mysql::DBCommand>(db_connect);
  if(!db_command) return -1;

//  tinker::mysql::DBResultSetPtr result = db_command->Query("describe `tamgr`;");
//  while(result && result->FetchNext()){
//    LOG(info, "Field: {}", result->GetString("Field"));
//    LOG(info, "Type: {}", result->GetString("Type"));
//    LOG(info, "Key: {}", result->GetString("Key"));
//    LOG(info, "Default: {}", result->GetString("Default"));
//    LOG(warn, "---------------------------");
//  }

  for (size_t idx = 0; idx < 100000; idx++) {
    tinker::mysql::DBResultSetPtr result = db_command->Query("select * from tatract;");
    while(result && result->FetchNext()){
      LOG(info, "tracid: {}", result->GetString("tracid"));
      LOG(info, "maid: {}", result->GetString("maid"));
      LOG(info, "acid: {}", result->GetString("acid"));
      LOG(info, "marketid: {}", result->GetString("marketid"));
      LOG(info, "hedgeflag: {}", result->GetString("hedgeflag"));
      LOG(info, "tracname: {}", result->GetString("tracname"));
      LOG(info, "currencyid: {}", result->GetString("currencyid"));
      LOG(info, "creator: {}", result->GetString("creator"));
      LOG(info, "createtime: {}", result->GetString("tracid"));
    }
    LOG(info, "-------------------------------------------");
    std::this_thread::sleep_for(std::chrono::seconds(10));
  }

  while (1){}

  return 0;
}
