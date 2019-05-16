package wxopencrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"sort"
)

type WXBizMsgCrypt struct {
	m_sToken          string
	m_sEncodingAESKey string
	m_sAppid          string
	m_sKey            []byte
	m_sIv             []byte
}

func NewWXBizMsgCrypt() *WXBizMsgCrypt {
	wbmc := &WXBizMsgCrypt{}
	return wbmc
}

// var GWXBizMsgCrypt = newWXBizMsgCrypt()

func (this *WXBizMsgCrypt) Init(sToken string, sEncodingAESKey string, sAppid string) {
	this.m_sToken = sToken
	this.m_sEncodingAESKey = sEncodingAESKey
	this.m_sAppid = sAppid

	key, err := base64.StdEncoding.DecodeString(this.m_sEncodingAESKey + "=")
	if err != nil || len(key) != kAesKeySize {
		panic(1)
	}
	this.m_sKey = append(this.m_sKey, key...)
	this.m_sIv = this.m_sKey[:kAesIVSize]
}

func (this *WXBizMsgCrypt) DecryptMsg(sMsgSignature string, sTimeStamp string, sNonce string, sPostData string) (ret int, sMsg string) {
	//1.validate xml format
	ret1, sEncryptMsg := this.GetEncryptMsg(sPostData)
	if 0 != ret1 {
		ret = WXBizMsgCrypt_ParseXml_Error
		return
	}

	//2.validate signature
	if 0 != this.ValidateSignature(sMsgSignature, sTimeStamp, sNonce, sEncryptMsg) {
		ret = WXBizMsgCrypt_ValidateSignature_Error
		return
	}

	//3.decode base64
	sAesData, err := base64.StdEncoding.DecodeString(sEncryptMsg)
	if err != nil {
		ret = WXBizMsgCrypt_DecodeBase64_Error
		return
	}

	//4.decode aes
	c, err := aes.NewCipher(this.m_sKey)
	if err != nil {
		ret = WXBizMsgCrypt_IllegalAesKey
		return
	}

	cbc := cipher.NewCBCDecrypter(c, this.m_sIv)
	cbc.CryptBlocks(sAesData, sAesData)

	// fmt.Println(string(sAesData))
	sNoEncryptData := DecodeInPKCS7(sAesData)
	// fmt.Println(string(sNoEncryptData))

	// 5. remove kRandEncryptStrLen str
	if len(sNoEncryptData) <= (kRandEncryptStrLen + kMsgLen) {
		ret = WXBizMsgCrypt_IllegalBuffer
		return
	}

	buf := bytes.NewBuffer(sNoEncryptData[kRandEncryptStrLen : kRandEncryptStrLen+kMsgLen])
	var iMsgLen int32
	binary.Read(buf, binary.BigEndian, &iMsgLen)

	if len(sNoEncryptData) <= (kRandEncryptStrLen + kMsgLen + int(iMsgLen)) {
		ret = WXBizMsgCrypt_IllegalBuffer
		return
	}

	//6. validate appid
	sAppid := string(sNoEncryptData[kRandEncryptStrLen+kMsgLen+iMsgLen:])
	if sAppid != this.m_sAppid {
		ret = WXBizMsgCrypt_ValidateAppid_Error
		return
	}
	sMsg = string(sNoEncryptData[kRandEncryptStrLen+kMsgLen : kRandEncryptStrLen+kMsgLen+iMsgLen])
	ret = WXBizMsgCrypt_OK
	return
}

/*
int WXBizMsgCrypt::EncryptMsg(const std::string &sReplyMsg,
	const std::string &sTimeStamp,
	const std::string &sNonce,
	std::string &sEncryptMsg)
{
if(0 == sReplyMsg.size())
{
return WXBizMsgCrypt_ParseXml_Error;
}

//1.add rand str ,len, appid
std::string sNeedEncrypt;
GenNeedEncryptData(sReplyMsg,sNeedEncrypt);

//2. AES Encrypt
std::string sAesData;
std::string sAesKey;
if(0 != GenAesKeyFromEncodingKey(m_sEncodingAESKey,sAesKey))
{
return WXBizMsgCrypt_IllegalAesKey;
}
if(0 != AES_CBCEncrypt(sNeedEncrypt, sAesKey, &sAesData))
{
return WXBizMsgCrypt_EncryptAES_Error;
}

//3. base64Encode
std::string sBase64Data;
if( 0!= EncodeBase64(sAesData,sBase64Data) )
{
return WXBizMsgCrypt_EncodeBase64_Error;
}

//4. compute signature
std::string sSignature;
if(0!=ComputeSignature(m_sToken, sTimeStamp, sNonce, sBase64Data, sSignature))
{
return WXBizMsgCrypt_ComputeSignature_Error;
}

//5. Gen xml
if(0 != GenReturnXml(sBase64Data, sSignature, sTimeStamp, sNonce, sEncryptMsg) )
{
return WXBizMsgCrypt_GenReturnXml_Error ;
}
return WXBizMsgCrypt_OK;
}

int WXBizMsgCrypt::AES_CBCEncrypt( const std::string & objSource,
const std::string & objKey, std::string * poResult )
{
return AES_CBCEncrypt( objSource.data(), objSource.size(),
objKey.data(), objKey.size(), poResult );
}

int WXBizMsgCrypt::AES_CBCEncrypt( const char * sSource, const uint32_t iSize,
const char * sKey,  uint32_t iKeySize, std::string * poResult )
{
if ( !sSource || !sKey || !poResult || iSize <= 0)
{
return -1;
}

poResult->clear();

int padding = kAesKeySize - iSize % kAesKeySize;

char * tmp = (char*)malloc( iSize + padding );
if(NULL == tmp)
{
return -1;
}
memcpy( tmp, sSource, iSize );
memset( tmp + iSize, padding, padding );

unsigned char * out = (unsigned char*)malloc( iSize + padding );
if(NULL == out)
{
FREE_PTR(tmp);
return -1;
}

unsigned char key[ kAesKeySize ] = { 0 };
unsigned char iv[ kAesIVSize ] = { 0 };
memcpy( key, sKey, iKeySize > kAesKeySize ? kAesKeySize : iKeySize );
memcpy(iv, key, sizeof(iv) < sizeof(key) ? sizeof(iv) : sizeof(key));

AES_KEY aesKey;
AES_set_encrypt_key( key, 8 * kAesKeySize, &aesKey );
AES_cbc_encrypt((unsigned char *)tmp, out,iSize + padding,  &aesKey, iv, AES_ENCRYPT);
poResult->append((char*)out, iSize + padding);

FREE_PTR(tmp);
FREE_PTR(out);
return 0;
}
*/

func (this *WXBizMsgCrypt) ComputeSignature(sToken string, sTimeStamp string, sNonce string, sMessage string) (ret int, sSignature string) {
	if 0 == len(sToken) || 0 == len(sNonce) || 0 == len(sMessage) || 0 == len(sTimeStamp) {
		ret = -1
		return
	}

	//sort
	var vecStr []string
	vecStr = append(vecStr, sToken)
	vecStr = append(vecStr, sTimeStamp)
	vecStr = append(vecStr, sNonce)
	vecStr = append(vecStr, sMessage)
	// std::sort( vecStr.begin(), vecStr.end() );
	sort.Strings(vecStr)
	sStr := vecStr[0] + vecStr[1] + vecStr[2] + vecStr[3]

	//compute
	h := sha1.New()
	h.Write([]byte(sStr))
	output := h.Sum(nil)

	// to hex
	for i := 0; i < len(output); i++ {
		// fmt.Sprintln(,)
		hexStr := fmt.Sprintf("%02x", 0xff&output[i])
		sSignature = sSignature + hexStr
	}
	return
}

func (this *WXBizMsgCrypt) ValidateSignature(sMsgSignature string, sTimeStamp string, sNonce string, sEncryptMsg string) int {
	ret, sSignature := this.ComputeSignature(this.m_sToken, sTimeStamp, sNonce, sEncryptMsg)
	if 0 != ret {
		return -1
	}

	if sMsgSignature != sSignature {
		return -1
	}

	return 0
}

// func (this *WXBizMsgCrypt) GenAesKeyFromEncodingKey(sEncodingKey string) (ret int, sAesKey string) {
// 	if kEncodingKeySize != len(sEncodingKey) {
// 		ret = -1
// 		return
// 	}

// 	var sBase64 = sEncodingKey + "="
// 	sAesKey0, err := base64.StdEncoding.DecodeString(sBase64)
// 	if err != nil || kAesKeySize != len(sAesKey0) {
// 		ret = -1
// 		return
// 	}

// 	sAesKey = string(sAesKey0)
// 	ret = 0
// 	return
// }

func (this *WXBizMsgCrypt) GetEncryptMsg(sPostData string) (ret int, sEncryptMsg string) {
	var vt VerifyTicketEncrypt
	xml.Unmarshal([]byte(sPostData), &vt)

	if len(vt.AppId) <= 0 || len(vt.Encrypt) <= 0 {
		ret = -1
		return
	}

	sEncryptMsg = vt.Encrypt
	return
}

/*
void WXBizMsgCrypt::GenRandStr(std::string & sRandStr, uint32_t len)
{
uint32_t idx = 0;
srand((unsigned)time(NULL));
char tempChar = 0;
sRandStr.clear();

while(idx < len)
{
tempChar = rand()%128;
if(isprint(tempChar))
{
sRandStr.append(1, tempChar);
++idx;
}
}
}

void WXBizMsgCrypt::GenNeedEncryptData(const std::string &sReplyMsg,std::string & sNeedEncrypt )
{
//random(16B)+ msg_len(4B) + msg + $AppId
std::string sRandStr;
GenRandStr(sRandStr,kRandEncryptStrLen);
uint32_t iXmlSize = sReplyMsg.size();
uint32_t iNSize  = htonl(iXmlSize);
std::string sSize ;
sSize.assign((const char *)&iNSize,sizeof(iNSize));

sNeedEncrypt.erase();
sNeedEncrypt = sRandStr;
sNeedEncrypt += sSize;
sNeedEncrypt += sReplyMsg;
sNeedEncrypt += m_sAppid;
}

int WXBizMsgCrypt::SetOneFieldToXml(tinyxml2::XMLDocument * pDoc, tinyxml2::XMLNode* pXmlNode, const char * pcFieldName,
const std::string & value, bool bIsCdata)
{
if(!pDoc || !pXmlNode || !pcFieldName)
{
return -1;
}

tinyxml2::XMLElement * pFiledElement = pDoc->NewElement(pcFieldName);
if(NULL == pFiledElement)
{
return -1;
}

tinyxml2::XMLText * pText = pDoc->NewText(value.c_str());
if(NULL == pText)
{
return -1;
}

pText->SetCData(bIsCdata);
pFiledElement->LinkEndChild(pText);

pXmlNode->LinkEndChild(pFiledElement);
return 0;
}

int WXBizMsgCrypt::GenReturnXml(const std::string & sEncryptMsg, const std::string & sSignature, const std::string & sTimeStamp,
const std::string & sNonce, std::string & sResult)
{
tinyxml2::XMLPrinter oPrinter;
tinyxml2::XMLNode* pXmlNode = NULL;
tinyxml2::XMLDocument * pDoc = new tinyxml2::XMLDocument();
if(NULL == pDoc)
{
return -1;
}

pXmlNode = pDoc->InsertEndChild( pDoc->NewElement( "xml" ) );
if(NULL == pXmlNode)
{
DELETE_PTR(pDoc);
return -1;
}

if(0 != SetOneFieldToXml(pDoc,pXmlNode,"Encrypt",sEncryptMsg,true))
{
DELETE_PTR(pDoc);
return -1;
}

if(0 != SetOneFieldToXml(pDoc,pXmlNode,"MsgSignature",sSignature,true))
{
DELETE_PTR(pDoc);
return -1;
}

if(0 != SetOneFieldToXml(pDoc,pXmlNode,"TimeStamp",sTimeStamp,true))
{
DELETE_PTR(pDoc);
return -1;
}

if(0 != SetOneFieldToXml(pDoc,pXmlNode,"Nonce",sNonce,true))
{
DELETE_PTR(pDoc);
return -1;
}

//ת��string
pDoc->Accept(&oPrinter);
sResult = oPrinter.CStr();

DELETE_PTR(pDoc);
return 0;
}
*/
