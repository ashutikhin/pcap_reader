/*! \file
 *  \brief Содержит точку входа программы.
 *  \author Антон Шутихин
 *  \date 2020.11.06
 */

#include <iostream>

#include "pcap_reader.hpp"

int main(int argc, char* argv[])
{
    std::string out = "./pcap_reader file.pcap [ip] [port]";
    if (argc < 2 || argc > 4)
    {
        std::cerr << out << std::endl;
        return -1;
    }

    std::string address;
    uint16_t port = 0;

    for (int i = 2; i < argc; ++i)
    {
        if (!PcapReader::check_ip(argv[i], address) && !PcapReader::check_port(argv[i], port))
        {
            std::cerr << out << std::endl;
            return -1;
        }
    }

    try
    {
        PcapReader reader(argv[1]);
        reader.filter(address, port);
        reader.process();
        reader.print();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return -1;
    }

    return 0;
}
