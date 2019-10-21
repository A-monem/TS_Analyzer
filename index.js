var fs = require('fs');


//create a stream of 188 bytes

const fileUrl = new URL('file:/d:/Web Dev/TransportStream/Self TS Analyzer/media/Tiny_Test_TS.ts');
const input = fs.createReadStream(fileUrl, { highWaterMark: 188 });
const { Transform } = require('stream');
let pat, pmt;

const readTransform = new Transform({
    transform(chunk, encoding, next) {
        let packet = readTSPackets(chunk);
        if (packet.pid === 0){
            readPAT(packet);
        }
        if (pat !== undefined && Object.values(pat).includes(packet.pid)){
            readPMT(packet);
        }
        next()
    }
});


//read TS packets and transform to JSON file

const readTSPackets = (chunk) => {
    const header = chunk.readUInt32BE(0); //first 4 bytes
    let packet = {
        type: "TSPacket",
        packetSync: (header & 0xff000000) >> 24,
        transportErrorIndicator: (header & 0x800000) !== 0,
        payloadUnitStartIndicator: (header & 0x400000) !== 0,
        transportPriority: (header & 0x200000) !== 0,
        pid: (header & 0x1fff00) >>> 8,
        scramblingControl: (header & 0xc0) >>> 6,
        adaptationFieldControl: (header & 0x30) >>> 4,
        continuityCounter: (header & 0xf)
    };

    //Check adaptation field 
    if ((packet.adaptationFieldControl & 0x02) !== 0) {
        let adaptationFieldLength = chunk.readUInt8(4);
        if (adaptationFieldLength === 0) {
            packet.adaptationField = {
                type: 'AdaptationField',
                adaptationFieldLength: 0
            };
        } else {
            let flags = chunk.readUInt8(5);
            packet.adaptationField = {
                type: 'AdaptationField',
                adaptationFieldLength: adaptationFieldLength,
                discontinuityIndicator: (flags & 0x80) !== 0,
                randomAccessIndicator: (flags & 0x40) !== 0,
                elementaryStreamPriorityIndicator: (flags & 0x20) !== 0,
                pcrFlag: (flags & 0x10) !== 0,
                opcrFlag: (flags & 0x08) !== 0,
                splicingPointFlag: (flags & 0x04) !== 0,
                transportPrivateDataFlag: (flags & 0x02) !== 0,
                adaptationFieldExtensionFlag: (flags & 0x01) !== 0
            }
        }
    }
    if ((packet.adaptationFieldControl & 0x01) !== 0) {
        packet.payload = packet.adaptationField ? 
        chunk.slice(5+packet.adaptationField.adaptationFieldLength):
        chunk.slice(4);
    }
    return packet;
};

//readt PAT table
const readPAT = (input) => {
        pat = {};
        let pointer, payloadLength;
        const payload = input.payload;
        const header = psiCollector(input)
        if (header.sectionSyntaxIndicator === 1){
            pointer = 9 
            payloadLength = header.sectionLength - 5
        } else {
            pointer = 4 
            payloadLength = header.sectionLength
        }
        for (let i=0; i< payloadLength-4; i+=4){
            const programNum = payload.readUInt16BE(pointer + i);
            const pmtPid = (payload.readUInt32BE(pointer + i) & 0x1fff);
            pat[programNum] = pmtPid;
        }
    header.sectionCRC = payload.readUInt32BE(pointer+payloadLength-4);
}

//read PMT tables
const readPMT = (input) => {
    pmt = {};
        const payload = input.payload;
        let pointer, payloadLength;
        const header = psiCollector(input)
        if (header.sectionSyntaxIndicator === 1){
            pointer = 9 
            payloadLength = header.sectionLength - 5
        } else {
            pointer = 4 
            payloadLength = header.sectionLength
        }
        header.pcr = payload.readUInt16BE(pointer) & 0x1fff;
        header.programInfoLength = payload.readUInt16BE(pointer+2) & 0x03ff;
        pointer += 4
        payloadLength -= 4
        let counter= 1
        while(payloadLength-4 > 0){
            let elementaryStream = {
                "streamType": streamTypeIDName[payload.readUInt8(pointer)],
                "pid": payload.readUInt16BE(pointer+1) & 0x1fff,
                "infoLength": (payload.readUInt16BE(pointer+3) & 0x03ff),
            }
            pmt[counter] = elementaryStream;
            payloadLength -= (5+elementaryStream.infoLength);
            pointer += (5+elementaryStream.infoLength);
            counter++
        }

        console.log(pmt);
}

//utilities
const psiCollector = (input) => {
    const payload = input.payload;
        let pointer = 1;  
        const header = {
            type: "PSISection",
            pid: input.pid,
            tableID: payload.readUInt8(pointer),
            sectionSyntaxIndicator: (payload.readUInt16BE(pointer+1) & 0x8000) >> 15,
            privateBit: (payload.readUInt16BE(pointer+1) & 0x4000) >> 14,
            sectionLength:  (payload.readUInt16BE(pointer+1) & 0x0fff), //number of bytes for sytanx section and table data
        };
        pointer +=3;
        if (header.sectionSyntaxIndicator === 1) {
            header.tableIDExtension = payload.readUInt16BE(pointer);
            header.versionNumber = (payload.readInt8(pointer + 2) & 0x3e) >> 1;
            header.currentNextIndicator = payload.readInt8(pointer + 2) & 0x01;
            header.sectionNumber = payload.readUInt8(pointer + 3);
            header.lastSectionNumber = payload.readUInt8(pointer + 4);
        }
    return header
}

let streamTypeIDName = {
    0x00 : 'ITU-T | ISO/IEC Reserved',
    0x01 : 'ISO/IEC 11172-2 Video',
    0x02 : 'ITU-T Rec. H.262 | ISO/IEC 13818-2 Video or ISO/IEC 11172-2 constrained parameter video stream',
    0x03 : 'ISO/IEC 11172-3 Audio',
    0x04 : 'ISO/IEC 13818-3 Audio',
    0x05 : 'ITU-T Rec. H.222.0 | ISO/IEC 13818-1 private_sections',
    0x06 : 'ITU-T Rec. H.222.0 | ISO/IEC 13818-1 PES packets containing private data',
    0x07 : 'ISO/IEC 13522 MHEG',
    0x08 : 'ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Annex A DSM-CC',
    0x09 : 'ITU-T Rec. H.222.1',
    0x0a : 'ISO/IEC 13818-6 type A',
    0x0b : 'ISO/IEC 13818-6 type B',
    0x0c : 'ISO/IEC 13818-6 type C',
    0x0d : 'ISO/IEC 13818-6 type D',
    0x0e : 'ITU-T Rec. H.222.0 | ISO/IEC 13818-1 auxiliary',
    0x0f : 'ISO/IEC 13818-7 Audio with ADTS transport syntax',
    0x10 : 'ISO/IEC 14496-2 Visual',
    0x11 : 'ISO/IEC 14496-3 Audio with the LATM transport syntax as defined in ISO/IEC 14496-3',
    0x12 : 'ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in PES packets',
    0x13 : 'ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in ISO/IEC 14496_sections',
    0x14 : 'ISO/IEC 13818-6 Synchronized Download Protocol',
    0x15 : 'Metadata carried in PES packets',
    0x16 : 'Metadata carried in metadata_sections',
    0x17 : 'Metadata carried in ISO/IEC 13818-6 Data Carousel',
    0x18 : 'Metadata carried in ISO/IEC 13818-6 Object Carousel',
    0x19 : 'Metadata carried in ISO/IEC 13818-6 Synchronized Download Protocol',
    0x1a : 'IPMP stream (defined in ISO/IEC 13818-11, MPEG-2 IPMP)',
    0x1b : 'AVC video stream as defined in ITU-T Rec. H.264 | ISO/IEC 14496-10 Video',
    0x7f : 'IPMP stream'
  };

// pipe read stream into transform stram
input.pipe(readTransform)

//update UI