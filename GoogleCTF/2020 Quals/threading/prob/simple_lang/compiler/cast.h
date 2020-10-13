#pragma once
#include <iostream>

template <typename RetType, typename InType>
RetType cast(InType in) {
  auto ret = dynamic_cast<RetType>(in);
  if (!ret) {
    std::cerr << "Unable to cast from object of type " << typeid(*in).name()
              << " to object of type " << typeid(ret).name() << std::endl;
  }
  assert(ret);
  return ret;
}