#define LOG_MODULE PacketLogModuleEspReassembly

#include "EspReassembly.h"
#include "EndianPortable.h"
#include "IPLayer.h"
#include "UdpLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include "IPSecLayer.h"
#include <sstream>
#include <vector>
#include "Packet.h"

namespace pcpp
{

//std::string ESPReassembly::getTupleName(IPAddress src, IPAddress dst, uint16_t srcPort, uint16_t dstPort)
std::string ESPReassembly::getTupleName(IPAddress src, IPAddress dst)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("esp");
	// 文件
	//stream << sourceIP << '.' << srcPort << '-' << destIP << '.' << dstPort << '-' << protocol;
    stream << sourceIP << '-' << destIP << '-' << protocol;

	// return the name
	return stream.str();
}

ESPReassembly::ReassemblyStatus ESPReassembly::reassemblePacket(RawPacket *espRawData)
{
	Packet parsedPacket(espRawData, false);
	return reassemblePacket(parsedPacket);
}

ESPReassembly::ReassemblyStatus ESPReassembly::reassemblePacket(Packet &espData)
{

    // connection list -》 tuple list
/* 	
    1. 获取目标包的内层的源IP和目的IP， 过滤非目标包
	2. 更新状态（返回值）
	3. 设置ESPReassemblyData
	   计算链接tupleName，在fragment list找目标fragment，若不存在则添加
	   再更新ESPReassemblyData 里的fragment信息
	4. 如果已经设置过回调函数，data调用该函数进行处理 
*/

    // 1. 
	IPAddress srcIP, dstIP;
	if (espData.isPacketOfType(IP))
	{
		
		//获取esp包内层的IP层
		const IPLayer *ipLayer = espData.getLayerOfType<IPLayer>(true);
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	    //PCPP_LOG_ERROR(srcIP);
	}
	else
		return NonIpPacket;

		//UDP层与IP层相同，通过将reverseOrder设置为true，
		//获取esp包内层的UDP层
/* 	uint16_t srcPort,dstPort;
	if (espData.isPacketOfType(UDP))
	{
		const UdpLayer *udpLayer = espData.getLayerOfType<UdpLayer>(true);
		srcPort = udpLayer->getSrcPort();
	    dstPort = udpLayer->getDstPort();
	}
   else
		return NonUdpPacket; */

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-ESP packets
	ESPLayer *espLayer = espData.getLayerOfType<ESPLayer>(true); // lookup in reverse order
	if (espLayer == NULL)
	{
		return NonEspPacket;
	}
    

    // 2.
	//标记状态
	ReassemblyStatus status = EspMessageHandled;

    // 3.

	ESPReassemblyData *espReassemblyData = NULL;
	//std::string tupleName = getTupleName(srcIP, dstIP, srcPort, dstPort);
    std::string tupleName = getTupleName(srcIP, dstIP);
	

	// 元组列表里找对应的
	FragmentList::iterator iter = m_FragmentList.find(tupleName);

	if (iter == m_FragmentList.end())
	{
		std::pair<FragmentList::iterator, bool> pair =
			m_FragmentList.insert(std::make_pair(tupleName, ESPReassemblyData()));
		espReassemblyData = &pair.first->second;
		espReassemblyData->srcIP = srcIP;
		espReassemblyData->dstIP = dstIP;
		//espReassemblyData->srcPort = srcPort;
		//espReassemblyData->dstPort = dstPort;
		espReassemblyData->tupleName = tupleName;
        espReassemblyData->number = 0;
	}

	// 包处理
	uint8_t *data = espLayer->getData();
	size_t len = espLayer->getDataLen();
	EspPacketData packetdata(data, len, tupleName);


    // 4.

	// send the data to the callback
	if (m_OnEspMessageReadyCallback != NULL)
	{
		m_OnEspMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp