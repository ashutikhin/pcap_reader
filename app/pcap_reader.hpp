/*! \file
 *  \brief Содержит объявление класса PcapReader.
 *  \author Антон Шутихин
 *  \date 2020.11.06
 */

#ifndef __PCAP_READER_HPP__
#define __PCAP_READER_HPP__

#include <iostream>
#include <unordered_map>

#include <boost/asio/ip/address_v4.hpp>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/UdpLayer.h>

class PcapReader
{
private:
    pcpp::PcapFileReaderDevice reader;
    std::unordered_map<std::string, std::pair<int, int>> packets;

public:
    PcapReader(const char* file) : reader(file)
    {
        if (!reader.open())
            throw std::runtime_error("Error opening the pcap file");
    }

    virtual ~PcapReader()
    {
        reader.close();
    }

    PcapReader(PcapReader&) = delete;
    PcapReader(PcapReader&&) = delete;

    PcapReader& operator=(PcapReader&) = delete;
    PcapReader& operator=(PcapReader&&) = delete;

    void filter(const std::string& ip = "", const uint16_t port = 0);

    void process();

    void print();

    static bool check_port(const char* str, uint16_t& port);

    static bool check_ip(const std::string& str, std::string& address);
};

#endif // __PCAP_READER_HPP__
