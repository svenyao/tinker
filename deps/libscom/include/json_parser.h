//
// Created by sven on 6/1/17.
//

#ifndef LIBSCOM_JSON_PARSER_H
#define LIBSCOM_JSON_PARSER_H

#include "lexical_cast.h"
#include "noncopyable.h"
#include "rapidjson/document.h"
#include "rapidjson/pointer.h"
#include "rapidjson/writer.h"
#include "rapidjson/istreamwrapper.h"

#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <memory>

namespace scom {

// json data source type
enum SourceType {
  kStString,
  kStFile,
};
// json member type
enum MemberType {
  kString, kNumber, kInt, kUint, kInt64, kUint64, kDouble, kBool, kObject, kArray
};

// JsonParser template define
template <class T>
struct JsonParser {
  static bool json_parse(const rapidjson::Value* node, T &value) {
    return true;
  }
};

typedef std::shared_ptr<rapidjson::Document> JsonDocumentPtr;
//
// JsonNode class impl
//
class JsonNode : public noncopyable {
 public:
  explicit JsonNode(const std::string& str, SourceType type = kStString, bool has_comment = false) {
    JsonDocumentPtr doc_ptr = std::make_shared<rapidjson::Document>();
    if (type == kStFile) {
      std::ifstream ifs(str, std::ios::binary);
      rapidjson::IStreamWrapper isw(ifs);
      if (has_comment)
        doc_ptr->ParseStream<rapidjson::kParseCommentsFlag|rapidjson::kParseTrailingCommasFlag>(isw);
      else
        doc_ptr->ParseStream<0>(isw);
    }
    else {
      if (has_comment)
        doc_ptr->Parse<rapidjson::kParseCommentsFlag>(str.data());
      else
        doc_ptr->Parse<0>(str.data());
    }

    if (doc_ptr->HasParseError()) {
      parse_error_ = doc_ptr->GetParseError();
    }
    else{
      doc_ptr_ = doc_ptr;
      value_pt_ = &(*doc_ptr_);
    }
  }
  explicit JsonNode(JsonDocumentPtr doc_ptr, rapidjson::Value* value_pt) {
    doc_ptr_ = doc_ptr;
    value_pt_ = value_pt;
  }
  virtual ~JsonNode() {}

  bool CheckMember(const std::string& key, MemberType type) {
    if(!doc_ptr_ || !value_pt_) return false;
    rapidjson::Value *value_pt = value_pt_;

    if (!key.empty() && !GetJsonValue(key, value_pt))
      return false;

    switch (type) {
      case kString: return value_pt->IsString();
      case kNumber: return value_pt->IsNumber();
      case kInt: return value_pt->IsInt();
      case kUint: return value_pt->IsUint();
      case kInt64: return value_pt->IsInt64();
      case kUint64: return value_pt->IsUint64();
      case kDouble: return value_pt->IsDouble();
      case kBool: return value_pt->IsBool();
      case kObject: return value_pt->IsObject();
      case kArray: return value_pt->IsArray();
      default:
        break;
    }
    return false;
  }

  template<class T>
  bool GetValue(const std::string& key, T& value) const {
    if(!doc_ptr_ || !value_pt_) return false;
    rapidjson::Value *value_pt = value_pt_;

    if (!key.empty() && !GetJsonValue(key, value_pt))
      return false;

    if (value_pt->IsObject() || value_pt->IsArray())
      return false;

    return JsonParser<T>::json_parse(value_pt, value);
  }

  template <class T>
  T GetValue(const std::string& key = "") const {
    if(!doc_ptr_ || !value_pt_) return std::move(T());

    rapidjson::Value *value_pt = value_pt_;
    if (!key.empty() && !GetJsonValue(key, value_pt))
      return std::move(T());

    std::ostringstream oss;
    switch (value_pt->GetType()) {
      case rapidjson::kStringType:
        oss << std::string(value_pt->GetString(), value_pt->GetStringLength());
        break;
      case rapidjson::kNumberType:{
        if(value_pt->IsInt()) oss << value_pt->GetInt();
        else if(value_pt->IsUint()) oss << value_pt->GetUint();
        else if(value_pt->IsInt64()) oss << value_pt->GetInt64();
        else if(value_pt->IsUint64()) oss << value_pt->GetUint64();
        else if(value_pt->IsDouble()) oss << value_pt->GetDouble();
        break;
      }
      case rapidjson::kTrueType:
      case rapidjson::kFalseType:{
        oss << std::boolalpha << value_pt->GetBool();
        break;
      }
      default:{
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        (*value_pt).Accept(writer);
        oss << buffer.GetString();
        break;
      }
    }
    return std::move(lexical_cast<T>(oss.str()));
  }

  std::shared_ptr<JsonNode> GetNode(const std::string& key) const {
    if(!doc_ptr_ || !value_pt_) return false;
    rapidjson::Value *value_pt;
    if (GetJsonValue(key, value_pt)) {
      std::shared_ptr<JsonNode> node_ptr = std::make_shared<JsonNode>(doc_ptr_, value_pt);
      node_ptr->set_key(key);
      return node_ptr;
    }
    return nullptr;
  }

  bool GetNodes(const std::string& key, std::vector<std::shared_ptr<JsonNode> >& node_arr) const {
    if(!doc_ptr_ || !value_pt_) return false;
    node_arr.clear();

    rapidjson::Value *value_pt = value_pt_;
    if (!key.empty() && !GetJsonValue(key, value_pt))
      return false;

    if (value_pt->IsObject()) {
      for(auto iter = value_pt->MemberBegin(); iter != value_pt->MemberEnd(); ++iter) {
        std::shared_ptr<JsonNode> node_ptr = std::make_shared<JsonNode>(doc_ptr_, &iter->value);
        node_ptr->set_key(iter->name.GetString());
        node_arr.push_back(node_ptr);
      }
      return true;
    }

    return false;
  }

  bool GetArray(const std::string& key, std::vector<std::shared_ptr<JsonNode> > &array) const {
    if(!doc_ptr_ || !value_pt_) return false;
    array.clear();
    rapidjson::Value *value_pt = value_pt_;
    if (!key.empty() && !GetJsonValue(key, value_pt))
      return false;

    if (value_pt->IsArray()) {
      for (rapidjson::SizeType i = 0; i < value_pt->Capacity(); ++i) {
        std::shared_ptr<JsonNode> node_ptr = std::make_shared<JsonNode>(doc_ptr_, &(*value_pt)[i]);
        node_ptr->set_key(key);
        array.push_back(node_ptr);
      }
      return true;
    }

    return false;
  }

  template<class T>
  bool SetValue(const std::string& key, const T& t) {
    if(key.empty()) return false;

    if(key[0] == '/') {
      rapidjson::Pointer(key.c_str()).Set(*value_pt_, t, doc_ptr_->GetAllocator());
    }
    else{
      rapidjson::Pointer(('/' + key).c_str()).Set(*value_pt_, t, doc_ptr_->GetAllocator());
    }

    return true;
  }

  bool RemoveNode(const std::string& key) {
    if (key.empty()) return false;

    bool result = false;
    if(key[0] == '/') {
      result = rapidjson::Pointer(key.c_str()).Erase(*value_pt_);
    }
    else{
      result = rapidjson::Pointer(('/' + key).c_str()).Erase(*value_pt_);
    }
    return result;
  }

  int GetParseError() const {
    return parse_error_;
  }
  std::string key() const {
    return key_;
  }

  rapidjson::Value* value() const {
    return value_pt_;
  }
 protected:
  bool GetJsonValue(const std::string& key, rapidjson::Value* &value) const {
    if (key.empty())
      return false;

    if (key[0] == '/') {
      value = rapidjson::Pointer(key.c_str()).Get(*value_pt_);
    }
    else {
      value = rapidjson::Pointer(("/" + key).c_str()).Get(*value_pt_);
    }

    return (value != nullptr);
  }

  void set_key(const std::string& key) {
    key_ = key;
  }
 private:
  JsonDocumentPtr doc_ptr_{nullptr};
  rapidjson::Value* value_pt_{nullptr};
  std::string key_{""};
  int parse_error_{0};
};

typedef std::shared_ptr<JsonNode> JsonNodePtr;

// JsonNode template impl
template<>
inline bool JsonNode::SetValue<std::string>(const std::string& key, const std::string& t) {
  return SetValue(key, t.data());
}

// JsonParser template impl
template <>
struct JsonParser<double>{
  static bool json_parse(const rapidjson::Value* node, double &value) {
    if (!node->IsDouble())
      return false;
    value = node->GetDouble();
    return true;
  }
};
template <>
struct JsonParser<std::string>{
  static bool json_parse(const rapidjson::Value* node, std::string &value) {
    if(!node->IsString())
      return false;
    value = node->GetString();
    return true;
  }
};
template <>
struct JsonParser<bool>{
  static bool json_parse(const rapidjson::Value* node, bool &value) {
    if(!node->IsBool())
      return false;
    value = node->GetBool();
    return true;
  }
};
template <>
struct JsonParser<int32_t>{
  static bool json_parse(const rapidjson::Value* node, int32_t &value) {
    if (!node->IsInt())
      return false;
    value = node->GetInt();
    return true;
  }
};
template <>
struct JsonParser<uint32_t>{
  static bool json_parse(const rapidjson::Value* node, uint32_t &value) {
    if(!node->IsUint())
      return false;
    value = node->GetUint();
    return true;
  }
};
template <>
struct JsonParser<int64_t>{
  static bool json_parse(const rapidjson::Value* node, int64_t &value) {
    if(!node->IsInt64())
      return false;
    value = node->GetInt64();
    return true;
  }
};
template <>
struct JsonParser<uint64_t>{
  static bool json_parse(const rapidjson::Value* node, uint64_t &value) {
    if(!node->IsUint64())
      return false;
    value = node->GetUint64();
    return true;
  }
};

}//!namespace scom

#endif //LIBSCOM_JSON_PARSER_H
