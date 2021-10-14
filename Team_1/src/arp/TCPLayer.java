package arp;

import java.util.*;

public class TCPLayer implements BaseLayer{
    public int nUpperLayerCount = 0;	
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;    
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();    
    private TCPHeader tcpHeader;
    
    // chat or file 을 구분하여 전달
    public boolean Send(byte[] input, int length){
    	
    	return true;
    }
    
    // header 설정
    private void inputHeaderData(byte[] tcpSegment, byte[] data) {
    }
    
    // 상위 레이어에 header를 제거한 데이터 전달
    public boolean Receive(byte[] input) {
        return this.GetUpperLayer(0).Receive(this.removeCapHeader(input));
    }
    
    // header 제거
    private byte[] removeCapHeader(byte[] input) {
        byte[] removedArray = new byte[input.length - 24];
        System.arraycopy(input, 24, removedArray, 0, removedArray.length);

        return removedArray;
    }

    // header 객체 생성 & 이름 설정
    public TCPLayer(String name){
    	this.tcpHeader = new TCPHeader();
    	this.pLayerName = name;
    }

	@Override
	public String GetLayerName() {
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
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);//layer異붽�
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);
	}

    private class TCPHeader {
        short tcpSrcPort;	// source port (2byte) 
        short tcpDstPort;	// destination port (2byte)
        int tcpSeq;			// sequence number (4byte)
        int tcpAck;			// acknowledged sequence (4byte)
        byte tcpOffset;		// no use (1byte)
        byte tcpFlag;		// control flag (1byte)
        short tcpWindow;	// no use (2byte)
        short tcpCksum;		// check sum (2byte)
        short tcpUrgptr;	// no use (2byte)
        byte[] padding;		// (4byte)
        byte[] tcpData;		// data part

        public TCPHeader() {
            this.padding = new byte[4];
        }

        byte[] shortToByteArray(short inputData) {
            byte[] arrayOfByte = new byte[2];
            arrayOfByte[0] = (byte) (inputData & 0xff);
            arrayOfByte[1] = (byte) ((inputData >> 8) & 0xff);

            return arrayOfByte;
        }

        byte[] intToByteArray(int inputData) {
            byte[] arrayOfByte = new byte[4];
            arrayOfByte[0] = (byte) (inputData & 0xff);
            arrayOfByte[1] = (byte) ((inputData >> 8) & 0xff);
            arrayOfByte[2] = (byte) ((inputData >> 16) & 0xff);
            arrayOfByte[3] = (byte) ((inputData >> 24) & 0xff);

            return arrayOfByte;
        }
    }
}
