#ifndef PACKETPP_ESP_REASSEMBLY
#define PACKETPP_ESP_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include <map>

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
class EspPacketData
{
  public:
	EspPacketData(const uint8_t *espData, size_t espDataLength, std::string tupleName)
		: m_Data(espData), m_DataLen(espDataLength), m_TupleName(tupleName)
	{
	}

	const uint8_t *getData() const
	{
		return m_Data;
	}

	size_t getDataLength() const
	{
		return m_DataLen;
	}

	std::string getTupleName()
	{
		return m_TupleName;
	}

  private:
	const uint8_t *m_Data;
	size_t m_DataLen;
	std::string m_TupleName;
};

class ESPReassembly
{
  public:
	/**
	 * @typedef OnEspMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnEspMessageReady)(pcpp::EspPacketData *espData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonEspPacket,
		EspMessageHandled,
		//NonUdpPacket,
	};

	ESPReassembly(OnEspMessageReady onEspMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnEspMessageReadyCallback(onEspMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}


	ReassemblyStatus reassemblePacket(Packet &espData);

	ReassemblyStatus reassemblePacket(RawPacket *espRawData);

//	std::string getTupleName(IPAddress src, IPAddress dst,uint16_t srcPort, uint16_t dstPort);
    std::string getTupleName(IPAddress src, IPAddress dst);

  private:
	struct ESPReassemblyData
	{
		IPAddress srcIP;
		IPAddress dstIP;
	//	uint16_t srcPort;
	//	uint16_t dstPort;
		std::string tupleName;
		uint16_t number;

		ESPReassemblyData()
		{
		}
		ESPReassemblyData(IPAddress src, IPAddress dst, uint16_t srcP, uint16_t dstP, std::string tName, uint16_t n)
		//	: srcIP(src), dstIP(dst), srcPort(srcP), dstPort(dstP), tupleName(tName), number(n)
            : srcIP(src), dstIP(dst), tupleName(tName), number(n)
		{
		}
	};

	typedef std::map<std::string, ESPReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnEspMessageReady m_OnEspMessageReadyCallback;
	void *m_CallbackUserCookie;
};

}// namespace pcpp

#endif /* PACKETPP_ESP_REASSEMBLY */