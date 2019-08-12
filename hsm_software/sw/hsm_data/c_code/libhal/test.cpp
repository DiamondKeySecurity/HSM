#include <iostream>
#include <memory>

extern "C"
{
#include "hal.h"
#include "xdr_internal.h"
}

#include "rpc_stream.h"
#include "safe_queue.h"
#include "rpc_packet.h"

int main()
{
    std::cout << "test" << std::endl;

    libhal::rpc_serial_stream serial_stream("/dev/ttyUSB0", 921600);
    serial_stream.start_read_thread();

    std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = std::shared_ptr<SafeQueue<libhal::rpc_packet>>(new SafeQueue<libhal::rpc_packet>());

    libhal::rpc_packet outpacket(2 * sizeof(uint32_t));
    outpacket.encode_int(0);
    outpacket.encode_int(0);

    serial_stream.write_packet(outpacket, 0, myqueue);

    libhal::rpc_packet inpacket = std::move(myqueue->dequeue());
    uint32_t code;
    uint32_t client;
    uint32_t result;
    uint32_t version;

    inpacket.decode_int(&code);
    inpacket.decode_int(&client);
    inpacket.decode_int(&result);
    inpacket.decode_int(&version);

    std::cout << "code: " << code << std::endl;
    std::cout << "client: " << client << std::endl;
    std::cout << "result: " << result << std::endl;
    std::cout << "version: " << version << std::endl;

    serial_stream.stop_read_thread();

    std::cin.ignore();

}