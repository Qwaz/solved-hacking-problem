#include <err.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <iterator>
#include <fstream>

#include "api.h"
#include "ipcz/node.h"
#include "ipcz/node_link.h"
#include "util/ref_counted.h"
#include "standalone/base/logging.h"
#include "reference_drivers/multiprocess_reference_driver.h"

struct IpczAPI ipcz_api = {
    .size = sizeof(ipcz_api),
};

void CheckIPCZ(IpczResult result, const char *fn)
{
  if (result != IPCZ_RESULT_OK)
  {
    errx(1, "%s failed with error %d", fn, result);
  }
}

int check(int res, const char *msg)
{
  if (res == -1)
    err(1, "%s", msg);
  return res;
}

IpczHandle main_node, sub_node;

void Get(IpczHandle portal, char *buf, uint32_t *buf_len)
{
  while (true)
  {
    IpczResult result = ipcz_api.Get(portal, IPCZ_NO_FLAGS, nullptr, buf,
                                     buf_len, nullptr, nullptr);
    if (result == IPCZ_RESULT_UNAVAILABLE)
    {
      usleep(1000);
      continue;
    }
    CheckIPCZ(result, "Get");
    return;
  }
}

void Put(IpczHandle portal, const char *buf, uint32_t buf_len)
{
  CheckIPCZ(
      ipcz_api.Put(portal, buf, buf_len, nullptr, 0, IPCZ_NO_FLAGS, nullptr),
      "Put");
}

void PrintNodeNames(ipcz::Node *node, const char *tag)
{
  std::cout << tag << " node name: " << node->GetAssignedName().ToString().c_str() << std::endl;

  ipcz::Ref<ipcz::NodeLink> link = node->GetBrokerLink();
  if (link != nullptr)
  {
    std::cout << tag << " router name: " << link->remote_node_name().ToString().c_str() << std::endl;
  }
  else
  {
    std::cout << tag << " router does not exist" << std::endl;
  }
}

void Check1337(ipcz::Node *node)
{
  ipcz::Ref<ipcz::NodeLink> link = node->GetLink(ipcz::NodeName(0x1337, 0x1337));
  if (link)
  {
    std::cout << "Node has 1337 link" << std::endl;
  }
  else
  {
    std::cout << "Node does not have 1337 link" << std::endl;
  }
}

int main(int argc, char *argv[])
{
  ipcz::standalone::SetVerbosityLevel(10);

#ifdef NDEBUG
  std::cout << "Not Debug" << std::endl;
#else
  std::cout << "Debug" << std::endl;
#endif

  std::cout << "Started running PoC" << std::endl;

  CheckIPCZ(IpczGetAPI(&ipcz_api), "IpczGetAPI");
  CheckIPCZ(ipcz_api.CreateNode(
                &ipcz::reference_drivers::kMultiprocessReferenceDriver,
                IPCZ_INVALID_DRIVER_HANDLE, IPCZ_NO_FLAGS, NULL, &main_node),
            "CreateNode");
  CheckIPCZ(ipcz_api.CreateNode(
                &ipcz::reference_drivers::kMultiprocessReferenceDriver,
                IPCZ_INVALID_DRIVER_HANDLE, IPCZ_NO_FLAGS, NULL, &sub_node),
            "CreateNode");

  ipcz::Node *main_node_ptr = ipcz::Node::FromHandle(main_node);
  ipcz::Node *sub_node_ptr = ipcz::Node::FromHandle(sub_node);

  IpczHandle portal;
  ipcz::reference_drivers::Channel channel(
      ipcz::reference_drivers::OSHandle(137));
  CheckIPCZ(
      ipcz_api.ConnectNode(
          main_node,
          ipcz::reference_drivers::CreateTransportFromChannel(
              std::move(channel), ipcz::reference_drivers::OSProcess(),
              ipcz::reference_drivers::MultiprocessTransportSource::
                  kFromNonBroker,
              ipcz::reference_drivers::MultiprocessTransportTarget::kToBroker),
          1, IPCZ_CONNECT_NODE_TO_BROKER, nullptr, &portal),
      "ConnectNode");

  std::cout << "Successfully created a portal to the broker" << std::endl;
  Put(portal, "Maybe", 5);

  ipcz::reference_drivers::Channel local_main, local_sub;
  std::tie(local_main, local_sub) =
      ipcz::reference_drivers::Channel::CreateChannelPair();

  IpczHandle portal_main, portal_sub;

  std::cout << "Before main-sub connection" << std::endl;
  PrintNodeNames(main_node_ptr, "Main");
  PrintNodeNames(sub_node_ptr, "Sub");
  Check1337(sub_node_ptr);

  CheckIPCZ(
      ipcz_api.ConnectNode(
          main_node,
          ipcz::reference_drivers::CreateTransportFromChannel(
              std::move(local_main), ipcz::reference_drivers::OSProcess(),
              ipcz::reference_drivers::MultiprocessTransportSource::
                  kFromNonBroker,
              ipcz::reference_drivers::MultiprocessTransportTarget::kToNonBroker),
          1, IPCZ_CONNECT_NODE_SHARE_BROKER, nullptr, &portal_main),
      "ConnectNode");

  CheckIPCZ(
      ipcz_api.ConnectNode(
          sub_node,
          ipcz::reference_drivers::CreateTransportFromChannel(
              std::move(local_sub), ipcz::reference_drivers::OSProcess(),
              ipcz::reference_drivers::MultiprocessTransportSource::
                  kFromNonBroker,
              ipcz::reference_drivers::MultiprocessTransportTarget::kToNonBroker),
          1, IPCZ_CONNECT_NODE_INHERIT_BROKER, nullptr, &portal_sub),
      "ConnectNode");

  std::cout << "Successfully created a sub node" << std::endl;

  std::cout << "After main-sub connection" << std::endl;
  PrintNodeNames(main_node_ptr, "Main");
  PrintNodeNames(sub_node_ptr, "Sub");
  Check1337(sub_node_ptr);

  char buf[1024];
  uint32_t buf_len = sizeof(buf) - 1;

  Put(portal_main, "Hello", 5);
  Get(portal_sub, buf, &buf_len);
  buf[buf_len] = 0;

  std::cout << "After message exchange" << std::endl;
  PrintNodeNames(main_node_ptr, "Main");
  PrintNodeNames(sub_node_ptr, "Sub");
  Check1337(sub_node_ptr);

  std::cout << "Local message exchange: " << buf << std::endl;

  int counter = 0;
  while (true)
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << "Tick " << counter++ << std::endl;
  }
}
