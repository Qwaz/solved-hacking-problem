#pragma once
#include <fstream>
#include <iostream>
#include <string>
#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>
using namespace tao::pegtl;
namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace parser {
template <typename AstNode>
void extend_node(std::unique_ptr<parse_tree::node>& node) {
  std::unique_ptr<parse_tree::node> ret(new AstNode());
  ret->begin = node->begin;
  ret->end = node->end;
  ret->children = std::move(node->children);
  ret->id = node->id;
  node = move(ret);
}

template <typename AstNode>
struct action_impl {
  template <typename Input>
  static void apply(const Input&, parse_tree::state& s) {
    extend_node<AstNode>(s.back());
  }
};
}  // namespace parser