package arp;

import java.util.*;

public class ARPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	public String pLayerName = null;

	public ARPLayer(String name) {
		this.pLayerName = name;
	}

	private class ARP_Addr {
		private byte[] mac_addr = new byte[6];
		private byte[] ip_addr = new byte[4];

		public ARP_Addr() {
			Arrays.fill(ip_addr, (byte) 0x00);
			Arrays.fill(mac_addr, (byte) 0x00);

			// for (int indexOfAddr = 0; indexOfAddr < mac_addr.length; ++indexOfAddr) {
//                this.mac_addr[indexOfAddr] = (byte) 0x00;
//            }
//            for (int indexOfAddr = 0; indexOfAddr < ip_addr.length; ++indexOfAddr) {
//                this.ip_addr[indexOfAddr] = (byte) 0x00;
//            }
		}
	}

	private class ARP_Header {
		byte[] arp_mac_type;
		byte[] arp_ip_type;
		byte arp_mac_addr_len;
		byte arp_ip_addr_len;
		byte[] arp_opcode;

		byte[] arp_srcMAC;
		byte[] arp_srcIP;
		byte[] arp_dstMAC;
		byte[] arp_dstIP;

		public ARP_Header() {
			this.arp_mac_type = new byte[2];
			this.arp_ip_type = new byte[2];
			this.arp_mac_addr_len = 0x06;
			this.arp_ip_addr_len = 0x04;
			this.arp_opcode = new byte[2];
			this.arp_srcMAC = new byte[6];
			this.arp_srcIP = new byte[4];
			this.arp_dstMAC = new byte[6];
			this.arp_dstIP = new byte[4];

			// Initialize header variables.
			Arrays.fill(arp_srcMAC, (byte) 0x00);
			Arrays.fill(arp_srcIP, (byte) 0x00);
			Arrays.fill(arp_dstMAC, (byte) 0x00);
			Arrays.fill(arp_dstIP, (byte) 0x00);
		}
	}

	public String getIP_With_Dots(byte[] input) {
		String srcIP_With_Dots = "";

		for (int i = 0; i < 4; i++) {
			String temp = Integer.toHexString(0xff & input[i]);
			srcIP_With_Dots.concat(temp);
			if (i != 3)
				srcIP_With_Dots.concat(".");
		}

		return srcIP_With_Dots;
	}

	public String getMAC_With_Hyphen(byte[] input) {
		String hexNumber = "";
		String srcMacAddressWithHyphen = "";
		for (int i = 0; i < 6; i++) {
			hexNumber = Integer.toHexString(0xff & input[i]);
			srcMacAddressWithHyphen.concat(hexNumber.toUpperCase());
			if (i != 5)
				srcMacAddressWithHyphen.concat("-");
		}

		return srcMacAddressWithHyphen;
	}

	public synchronized boolean Receive(byte[] input) {
		ARP_Header response_header = new ARP_Header();

		// index MUST be FIXED !!!!!!!
		byte[] opcode = Arrays.copyOfRange(input, 6, 8);
		byte[] src_mac_address = Arrays.copyOfRange(input, 8, 14);
		byte[] src_ip_address = Arrays.copyOfRange(input, 14, 18);
		byte[] dst_ip_address = Arrays.copyOfRange(input, 24, 28);
		ChatFileDlg dlg = ((ChatFileDlg) this.GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0).GetUpperLayer(0));
		byte[] myIP = dlg.getMyIPAddress().getAddress(); // No intelligence copy

		if (opcode[0] == 0x00 && opcode[1] == 0x01) { // if ARP request

			if (Arrays.equals(src_ip_address, dst_ip_address)) { // GARP
//				1. GARP => srcIP에 해당하는 MAC이 table의 srcIP에 해당하는 MAC과 다른 경우
				// table을 수정해주면 됨.

				// Byte들로 이루어진 IP를 Dot을 찍어서 새로운 String으로 반환
				String srcIP_With_Dots = this.getIP_With_Dots(src_ip_address);

//				Byte들로 이루어진 MAC를 Dot을 찍어서 새로운 String으로 반환
				String srcMacAddressWithHyphen = this.getMAC_With_Hyphen(src_mac_address);

				// IP가 같은 row를 table에서 찾아서 그 row의 MAC정보를 수정
				for (int i = 0; i < dlg.getRowCountOfDTM_ARP(); ++i) {
					if (dlg.getValueOfDTM_ARP(i, 0).equals(srcIP_With_Dots)) {
						dlg.setValueOfDTM_ARP(srcMacAddressWithHyphen, i, 1); // column 1 - MAC Address
						break;
					}
				}

				return true;
			}

			else if (Arrays.equals(dst_ip_address, myIP)) {
				// 2. 단순 ARP => dstIP == myIP,
				// 상대 IP, MAC 정보 빼내면 되는것임.
				String inputRow[] = { this.getIP_With_Dots(src_ip_address), this.getMAC_With_Hyphen(src_mac_address),
						"Complete" };
				dlg.dtm_ARP.addRow(inputRow);

				response_header.arp_srcMAC = dlg.myMacByte;
				response_header.arp_srcIP = dst_ip_address;
				response_header.arp_dstMAC = src_mac_address;
				response_header.arp_dstIP = src_ip_address;
			}

			else {
				// 3. Proxy ARP => dstIP != myIP
				// 이것도 상대 IP, MAC 정보 빼내면 됨
				String srcIP_With_Dots = this.getIP_With_Dots(src_ip_address);
				String returnMAC_Address;
				Boolean isInProxyEntry = false;
				String myMacAddressWithHyphen = dlg.myMac;

//				dstIP랑 같은걸 찾아서 MAC을 반환
				for (int i = 0; i < dlg.dtm_PARP.getRowCount(); ++i) {
					if (dlg.getValueOfDTM_PARP(i, 0).equals(srcIP_With_Dots)) {
						returnMAC_Address = myMacAddressWithHyphen;
						isInProxyEntry = true;
						break;
					}
				}

				if (isInProxyEntry == false) { // if not in the Proxy Entry
					return false;
				}

				response_header.arp_srcMAC = dlg.myMacByte;
				response_header.arp_srcIP = dst_ip_address;
				response_header.arp_dstMAC = src_mac_address;
				response_header.arp_dstIP = src_ip_address;
			}

			// 0x02 : ARP Reply => ARP를 받은 후 답장을 위한 부분
			//	encapsulation
			byte[] response_arp = ObjToByte_Send(response_header, (byte) 0x02);
			
			//	Send ARP Reply
			return this.GetUnderLayer().Send(response_arp, response_arp.length);
		}

		else if (opcode[0] == 0x00 && opcode[1] == 0x02) {// 내가 보낸 ARP 요청이 돌아옴 (상대방이 주소를 넣어서 보냄)
			// table에서 IP가 같은것의 MAC주소를 갱신
			for (int i = 0; i < dlg.dtm_ARP.getRowCount(); ++i) {
				if (dlg.getValueOfDTM_ARP(i, 0).equals(getIP_With_Dots(src_ip_address))) {
					dlg.setValueOfDTM_ARP(getMAC_With_Hyphen(src_mac_address), i, 1);
					break;
				}
			}

			return true;
		}

		return false;
	}

	public byte[] ObjToByte_Send(ARP_Header Header, byte opcode) {
		byte[] buf = new byte[28]; // ARP Frame
		byte[] src_mac = Header.arp_srcMAC;
		byte[] src_ip = Header.arp_srcIP;
		byte[] dst_mac = Header.arp_dstMAC;
		byte[] dst_ip = Header.arp_dstIP;

		buf[0] = 0x00;
		buf[1] = 0x01;// Hard
		buf[2] = 0x08;
		buf[3] = 0x00;// protocol
		buf[4] = Header.arp_mac_addr_len;// 1바이트
		buf[5] = Header.arp_ip_addr_len;// 2바이트
		buf[6] = 0x00;
		buf[7] = opcode;
		System.arraycopy(src_mac, 0, buf, 8, 6);// 6바이트
		System.arraycopy(src_ip, 0, buf, 14, 4);// 4바이트
		System.arraycopy(dst_mac, 0, buf, 18, 6);// 6바이트
		System.arraycopy(dst_ip, 0, buf, 24, 4);// 4바이트

		return buf;
	}

	@Override
	public String GetLayerName() {
		// TODO Auto-generated method stub
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		if (p_UnderLayer == null)
			return null;
		return p_UnderLayer;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
		if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
			return null;
		return p_aUpperLayer.get(nindex);
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		if (pUnderLayer == null)
			return;
		this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);// layer異붽�
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);
	}

	public static boolean containMacAddress(byte[] addr) {
		// TODO Auto-generated method stub
		return false;
	}

}
