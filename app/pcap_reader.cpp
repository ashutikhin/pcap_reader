/*! \file
 *  \brief Содержит определение класса PcapReader.
 *  \author Антон Шутихин
 *  \date 2020.11.06
 */

#include "pcap_reader.hpp"

void PcapReader::filter(const std::string& ip, const uint16_t port)
{
    pcpp::ProtoFilter protocolFilter(pcpp::UDP);
    pcpp::PortFilter portFilter(port, pcpp::DST);
    pcpp::IPFilter ipFilter(ip, pcpp::DST);

    pcpp::AndFilter andFilter;

    andFilter.addFilter(&protocolFilter);

    if (port)
        andFilter.addFilter(&portFilter);

    if (!ip.empty())
        andFilter.addFilter(&ipFilter);

    if (!reader.setFilter(andFilter))
        throw std::logic_error("Error setting filters to the pcap file");
}

void PcapReader::process()
{
    pcpp::RawPacket rawPacket;

    while (reader.getNextPacket(rawPacket))
    {
        pcpp::Packet parsedPacket(&rawPacket);

        if (parsedPacket.isPacketOfType(pcpp::IPv4))
        {
            auto parsed = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            auto size = parsed->getDataLen();

            pcpp::IPv4Address srcIP = parsed->getSrcIpAddress();
            pcpp::IPv4Address destIP = parsed->getDstIpAddress();

            pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();

            auto src_port = htons(udpLayer->getUdpHeader()->portSrc);
            auto dst_port = htons(udpLayer->getUdpHeader()->portDst);

            std::string temp = srcIP.toString() + ":" + std::to_string(src_port) + " " + destIP.toString() + ":" + std::to_string(dst_port);
            if (packets.count(temp))
            {
                packets[temp].first++;
                packets[temp].second += size;
            }
            else
            {
                packets.emplace(temp, std::make_pair(1, size));
            }
        }
    }
}

void PcapReader::print()
{
    int count = 0;
    for (const auto& x : packets)
        std::cout << count++ << " " << x.first << " " << x.second.first << " " << x.second.second << "\n";
}

bool PcapReader::check_ip(const std::string& str, std::string& address)
{
    if (!address.empty())
        return false;

    boost::system::error_code ec;
    boost::asio::ip::address_v4::from_string(str, ec);

    if (!ec)
    {
        address = str;
        return true;
    }

    return false;
}

bool PcapReader::check_port(const char* str, uint16_t& port)
{
    if (port)
        return false;

    char *end;
    long val = strtol(str, &end, 10);
    if (!(errno || end == str || *end != '\0' || val < 0 || val >= 0x10000))
    {
        port = (uint16_t)val;
        return true;
    }

    return false;
}
