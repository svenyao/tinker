//
// Created by sven on 6/4/17.
//

#ifndef TINKER_DB_ENGINE_TEST_H
#define TINKER_DB_ENGINE_TEST_H

#include "logging.h"
#include "mysql_engine.h"
#include "sqlite_engine.h"
#include "lexical_cast.h"
#include "crypto.h"

#include "lock_queue.h"
#include "json_parser.h"
#include "hardware.h"

using namespace scom;

namespace tinker{

int mysql_engine_test(){
  // open database
  tinker::mysql::DBConnectPtr db_connect = std::make_shared<tinker::mysql::DBConnect>();
  if(db_connect->Connect("192.168.17.1:3306", "ison2", "ison2&lhhj", "ison26") == 0){
    LOG(info, "connect successfull.");
  }
  else{
    LOG(error, "connect failed.");
  }
  tinker::mysql::DBCommandPtr db_command = std::make_shared<tinker::mysql::DBCommand>(db_connect);
  if(!db_command) return -1;

  tinker::mysql::DBResultSetPtr result = db_command->Query("select * from taact");
  while(result && result->FetchNext()){
    LOG(info,"acid:{}", result->GetString("acid"));
    LOG(info,"id:{}", result->GetInt("id"));
    LOG(info,"caid:{}", result->GetString("caid"));
    LOG(info,"acname:{}", result->GetString("acname"));
    LOG(info,"actype:{}", result->GetString("actype"));
    LOG(info,"amt:{}", result->GetDouble("amt"));
    LOG(info,"validamt:{}", result->GetString("validamt"));
  }
  return 0;
}

int sqlite_engine_test(){
  tinker::sqlite::DBConnectPtr db_connect_ptr = std::make_shared<tinker::sqlite::DBConnect>();
  if(db_connect_ptr->Connect("test.db", "") == 0){
    LOG(info,"connect successfull.");
    //db_connect_ptr->ResetKey("", "123");
  }
  else{
    LOG(error,"connect failed.");
  }
  tinker::sqlite::DBCommandPtr db_command_ptr = std::make_shared<tinker::sqlite::DBCommand>(db_connect_ptr);
  if(!db_command_ptr) return -1;

  // create table
  std::string sql_str = "CREATE TABLE COMPANY("
         "ID INT PRIMARY KEY     NOT NULL,"
         "NAME           TEXT    NOT NULL,"
         "AGE            INT     NOT NULL,"
         "ADDRESS        CHAR(50),"
         "SALARY         REAL );";
  int ret_code = db_command_ptr->Update(sql_str);
  if(ret_code == 0){
    // insert
    sql_str = "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) "
        "VALUES (1, 'Paul', 32, 'California', 20000.00 ); "
        "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) "
        "VALUES (2, 'Allen', 25, 'Texas', 15000.00 ); "
        "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY)"
        "VALUES (3, 'Teddy', 23, 'Norway', 20000.00 );"
        "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY)"
        "VALUES (4, 'Mark', 25, 'Rich-Mond ', 65000.00 );";
    ret_code = db_command_ptr->Update(sql_str);
    if(ret_code != 0) return -1;
  }

  sql_str = "SELECT * from COMPANY";
  tinker::sqlite::DBResultSetPtr result = db_command_ptr->Query(sql_str);
  while(result && result->FetchNext()){
    LOG(debug,"ID:{},NAME:{}, AGE:{},ADDRESS:{}, SALARY:{}",
        result->GetString("ID"), result->GetString("NAME"),
        result->GetString("AGE"), result->GetString("ADDRESS"),
        result->GetString("SALARY"));
  }

  return 0;
}

int lexical_cast_test(){
  //bool
  LOG(debug, "bool false = {}", lexical_cast<bool>("false"));
  // double
  LOG(debug, "double 1234.456427 = {}", lexical_cast<double>("1234.456427"));
  // int32_t
  LOG(debug,"int32_t 1230000000 = {}", lexical_cast<int32_t>("1230000000"));
  // uint32_t
  LOG(debug,"uint32_t 3800000091 = {}", lexical_cast<uint32_t>("3800000091"));
  // int64_t
  LOG(debug,"int64_t 9010001002000100002 = {}", lexical_cast<int64_t>("9010001002000100002"));
  // uint64_t
  LOG(debug,"uint64_t 15000200020001000100 = {}", lexical_cast<uint64_t>("15000200020001000100"));
  return 0;
}

int crypto_test(){
  std::string input = "hello world. source code.";
  std::string output;
  std::string key = "key123";
  Crypto crypto;
  if(crypto.Encrypt(input, key, output) != 0){
    LOG(error, "encrypt failed.");
    return -1;
  }
  std::string base_str;
  Base64::Encode(output, base_str);
  LOG(debug, "decrypt:{}", base_str);
  output.clear();
  Base64::Decode(base_str, output);
  std::string src_str;
  if(crypto.Decrypt(output, key, src_str) != 0){
    LOG(error, "Decrypt failed.");
    return -1;
  }
  LOG(debug, "decrypt:{}", src_str);
  return 0;
}

int hardware_test() {
  std::string temp;

  Hardware::GetCpuID(temp);
  LOG(warn, "cpuid:[{}]", temp);
  temp.clear();
  Hardware::GetDiskSN(temp);
  LOG(warn, "dsn:[{}]", temp);
  temp.clear();
  Hardware::GetMac(temp);
  LOG(warn, "mac:[{}]", temp);
  temp.clear();
  Hardware::GetLocalIp(temp);
  LOG(warn, "ip:[{}]", temp);

  std::string ip, mac;
  ip = "127.0.0.1"; mac = "";
  LOG(trace, "test input ip:{}", ip);
  Hardware::GetNetDevice(mac, ip);
  LOG(warn, "ip:{}, mac:{}", ip, mac);
  ip = ""; mac = "";
  LOG(trace, "test input ip:{}", ip);
  Hardware::GetNetDevice(mac, ip);
  LOG(warn, "ip:{}, mac:{}", ip, mac);
  ip = "172.16.1.52"; mac = "";
  LOG(trace, "test input ip:{}", ip);
  Hardware::GetNetDevice(mac, ip);
  LOG(warn, "ip:{}, mac:{}", ip, mac);
  ip = "172.16.1.62"; mac = "";
  LOG(trace, "test input ip:{}", ip);
  Hardware::GetNetDevice(mac, ip);
  LOG(warn, "ip:{}, mac:{}", ip, mac);
  return 0;
}

void lock_queue_test(){
  lock_queue<std::shared_ptr<int>> queue_;

  std::thread thd_1([&](){
    for(int idx = 0; idx < 100; ++idx){
      LOG(debug,"thread 1 push: {}" ,idx);
      queue_.push(std::make_shared<int>(idx));
      //tinker::s_sleep(1);
    }
  });

  // thread 2 pop.
  std::thread thd_2([&](){
    while (true){
      std::shared_ptr<int> val = nullptr;
      if(queue_.try_pop(val)){
        LOG(info,"thread 2 pop: {}", *val.get());
      }
      //LOG(info,"thread 2 pop: {}", *queue_.WaitAndPop().get();
      std::this_thread::sleep_for(std::chrono::seconds(1));
    };
  });
  // thread 3 pop
  std::thread thd_3([&](){
    while (true){
//      std::shared_ptr<int> val = nullptr;
//      if(queue_.TryPop(val)){
//        LOG(info,"thread 3 pop: {}", *val.get();
//      }
      LOG(info,"thread 3 pop: {}", *queue_.wait_and_pop().get());
      std::this_thread::sleep_for(std::chrono::seconds(1));
    };
  });

  thd_1.detach();
  thd_2.detach();
  thd_3.join();
};

void config_parser_test(){
  std::string json_str = "{ \"no\": 2, \"name\": \"5432\", \"node\":{\"name2\": \"tname2\"}"
      ",\"array\" :[\"art\", \"tra\"/*, \"test_comment\"*/]}";

  LOG(warn, "base json parse and test.");
  LOG(trace, "json: {}", json_str);
  std::shared_ptr<JsonNode> node_ptr = std::make_shared<JsonNode>((const std::string)json_str, kStString, true);
  if(node_ptr->GetParseError() != 0){
    LOG(error,"json parse failed.");
    return;
  }
  LOG(info, "json parse success.");

  std::string name_;
  node_ptr->GetValue("name", name_);
  int no_;
  node_ptr->GetValue("no", no_);
  LOG(info, "no: {}, name: {}" , no_, name_);

  std::string name2;
  node_ptr->GetValue("node/name2", name2);
  LOG(info,"name2: {}", name2);

  node_ptr->SetValue("node/name_t3", "namet3");
  node_ptr->SetValue("test", 134);

  std::shared_ptr<JsonNode> node_ptr2 = node_ptr->GetNode("node");
  std::string name3;
  node_ptr2->GetValue("name2", name3);
  LOG(info, "name2: {}", name3);

  LOG(info, "no:{}, name:{}, null:{}", node_ptr->GetValue<int>("no"),
      node_ptr->GetValue<double>("name"), node_ptr->GetValue<int64_t>("null"));
  LOG(info, "node:{}", node_ptr->GetValue<std::string>("node"));
  LOG(info, "array: {}", node_ptr->GetValue<std::string>("array"));

  LOG(warn, "array node parse test.");
  LOG(trace, "json:{}", json_str);

  std::vector<std::shared_ptr<JsonNode>> array_node;
  node_ptr->GetArray("array", array_node);
  for(auto iter : array_node){
    LOG(info, "array key: {}, value:{}", iter->key(), iter->GetValue<std::string>());
  }
  LOG(trace, "json:{}", node_ptr->GetValue<std::string>());

  LOG(warn, "test error json parse.");
  std::string json_str2 = "{ \"no\": 2x, \"name\": \"5432\", \"node\":{\"name2\": \"tname2\"},\"array\" :[\"art\", \"tra\",]}";
  LOG(trace, "json:{}", json_str2);

  std::shared_ptr<JsonNode> node2_ptr = std::make_shared<JsonNode>(json_str2);
  if(node2_ptr->GetParseError() != 0){
    LOG(error, "json parse failed.");
  }
  else {
    LOG(info, "json parse success.");
  }
  std::string json_str3 = "123456789";
  LOG(trace, "json:{}", json_str3);
  std::shared_ptr<JsonNode> node2_3_ptr = std::make_shared<JsonNode>(json_str3);
  if(node2_3_ptr->GetParseError() != 0){
    LOG(error, "json parse failed.");
  }
  else {
    LOG(info, "json parse success. get key:id, value:[{}]", node2_3_ptr->GetValue<std::string>("id"));
  }

  LOG(warn, "multi node parse test.");
  std::string json_t3 = "{\"endpoint\":{\"t1\":{\"name\":\"ss\"}, \"t2\":\"ogs\", \"t3\":{\"name\":\"store\"}}}";
  LOG(trace, "json:{}", json_t3);

  std::shared_ptr<JsonNode> node3_ptr = std::make_shared<JsonNode>(json_t3);
  if(node3_ptr->GetParseError() != 0){
    LOG(error, "json3 parse failed.");
  }
  std::vector<std::shared_ptr<JsonNode>> node_arr;
  node3_ptr->GetNodes("endpoint", node_arr);
  for(auto iter : node_arr){
    LOG(info, "nodes key: {}, value: {}", iter->key(), iter->GetValue<std::string>());
  }

  // test add array node.
  LOG(warn, "add array node[array_t] test. ");
  LOG(trace, "json:{}", node3_ptr->GetValue<std::string>());

  std::shared_ptr<JsonNode> array_node_ptr = std::make_shared<JsonNode>("[]", kStString);
  if(array_node_ptr->GetParseError() != 0){
    LOG(error, "array_node_ptr parse failed.");
  }
  for (int i = 0; i < 3; ++i) {
    std::shared_ptr<JsonNode> arr_item_node = std::make_shared<JsonNode>("{}", kStString);
    arr_item_node->SetValue("value1", i + 1000);
    arr_item_node->SetValue("value2", i + 2000);
    std::string val = "value3";
    arr_item_node->SetValue("value3", val);
    array_node_ptr->SetValue("/-", *(arr_item_node->value()));
  }
  //LOG(trace, "after json:{}", array_node_ptr->GetValue<std::string>());

  node3_ptr->SetValue("array_t", *array_node_ptr->value());
  LOG(info, "json:{}", node3_ptr->GetValue<std::string>());

  //
  LOG(warn, "remove node test. remove t3 node");
  node3_ptr->RemoveNode("/endpoint/t3");
  LOG(info, "json:{}", node3_ptr->GetValue<std::string>());

  //
  LOG(warn, "parse file test. not have comments.");
  JsonNodePtr nf_ptr = std::make_shared<JsonNode>("test.json", kStFile);
  if(nf_ptr->GetParseError() != 0){
    LOG(error, "node file parse failed. file:[{}]", "test.json");
  }
  LOG(info, "json:[{}], test:[{}]", nf_ptr->GetValue<std::string>(), nf_ptr->GetValue<std::string>("test"));

  LOG(warn, "parse file test. have comments.");
  JsonNodePtr nf2_ptr = std::make_shared<JsonNode>("test2.json", kStFile, true);
  if(nf2_ptr->GetParseError() != 0){
    LOG(error, "node file parse failed. file:[{}]", "test2.json");
  }
  LOG(info, "json:[{}], test:[{}]", nf2_ptr->GetValue<std::string>(), nf2_ptr->GetValue<std::string>("test"));
}

}//!namespace tinker.

#endif //TINKER_DB_ENGINE_TEST_H
