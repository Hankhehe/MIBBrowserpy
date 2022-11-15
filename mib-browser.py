from pysnmp.hlapi import *
import xml.etree.cElementTree as ET
from xml.dom import minidom

SoreceIP = input('Source IP :')
SwitchIP = input('Switch IP :')
SNMPVersion = input('SNMP Version 1 or 2 or 3 : ')
if not SNMPVersion : SNMPVersion = '2' #Default SNMPv2
DefaultOID = input('default OID ex .1.3 : ')
if not DefaultOID : DefaultOID = '.1.3' #Default .1.3
SNMPv3user,SNMPv3Auth,SNMPv3Privacy =None,None,None
AuthProtocol = usmHMACMD5AuthProtocol #it's Default is MD5
PrivacyProtocol = usmDESPrivProtocol #it's Default is DES

if SNMPVersion == '1':
    CommunityString = input('Community String ex public :')
    if not CommunityString : CommunityString = 'public' #Default community Str is public
    iterator = nextCmd(
    SnmpEngine(),
    CommunityData(CommunityString, mpModel=0),
    UdpTransportTarget((SwitchIP, 161)).setLocalAddress(SoreceIP),
    
    ContextData(),
    ObjectType(ObjectIdentity(DefaultOID)))

elif SNMPVersion == '3':
    SNMPv3user = input('SNMPv3user :')
    isauth = input('need auth y/n ?')
    if isauth == 'y' or isauth == 'Y' :
        SNMPv3Auth = input('Auth Key :')
        Authoption = input('1 = SHA\nNone = MD5\nAuth protocol :')
        if Authoption == '1' : AuthProtocol = usmHMACSHAAuthProtocol # SHA

        isprivacy = input('need privacy y/n ?')
        if isprivacy == 'y' or isprivacy == 'Y':
            SNMPv3Privacy = input('Privacy Key :')
            Privacyoption = input('1 = AES128\n2 = AES192\n3 = AES256\n4=3DES\nNone=DES\nPrivacy protocol : ')
            if Privacyoption == '1': PrivacyProtocol = usmAesCfb128Protocol #AES128
            elif Privacyoption == '2': PrivacyProtocol = usmAesCfb192Protocol #AES192
            elif Privacyoption == '3': PrivacyProtocol = usmAesCfb256Protocol #AES256
            elif Privacyoption == '4': PrivacyProtocol = usm3DESEDEPrivProtocol #3DES

    if SNMPv3Auth and SNMPv3Privacy:
        iterator = nextCmd(
        SnmpEngine(),
        UsmUserData(SNMPv3user, SNMPv3Auth,SNMPv3Privacy,
                authProtocol=AuthProtocol,
                privProtocol=PrivacyProtocol),
        UdpTransportTarget((SwitchIP, 161)).setLocalAddress((SoreceIP,0)),
        ContextData(),
        ObjectType(ObjectIdentity(DefaultOID)))

    elif SNMPv3Auth :
        iterator = nextCmd(
        SnmpEngine(),
        UsmUserData(SNMPv3user, SNMPv3Auth,authProtocol=AuthProtocol),
        UdpTransportTarget((SwitchIP, 161)).setLocalAddress((SoreceIP,0)),
        ContextData(),
        ObjectType(ObjectIdentity(DefaultOID)))

    else:
        iterator = nextCmd(
        SnmpEngine(),
        UsmUserData(SNMPv3user),
        UdpTransportTarget((SwitchIP, 161)).setLocalAddress((SoreceIP,0)),
        ContextData(),
        ObjectType(ObjectIdentity(DefaultOID)))
else:
    CommunityString = input('Community String :')
    if not CommunityString : CommunityString = 'public' #Default community Str is public
    iterator = nextCmd(
    SnmpEngine(),
    CommunityData(CommunityString),
    UdpTransportTarget((SwitchIP, 161)).setLocalAddress((SoreceIP,0)),
    ContextData(),
    ObjectType(ObjectIdentity(DefaultOID)))    

Exportileformat = input('Export File format: 1=xml 2=snmprec :')
if not Exportileformat : Exportileformat = '2'
SnmpSimulatorData = ET.Element('SnmpSimulatorData')
Instances = ET.SubElement(SnmpSimulatorData, 'Instances')

for errorIndication, errorStatus, errorIndex, varBinds in iterator:

    if errorIndication:
        print(errorIndication)
        break

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        break

    else:
        if Exportileformat == '1' :
            for varBind in varBinds:
                OidName = varBind[0]._ObjectIdentity__symName
                OiD = '.'+'.'.join([ str(x) for x in varBind[0]._ObjectIdentity__oid._value]) 
                Value = varBind[1].subtype().prettyPrint()
                ValueType = varBind[1].subtype().prettyPrintType()
                ValueType = str(ValueType[str(ValueType).index('->')+3::])
                Instance = ET.SubElement(Instances, 'Instance', name=OidName,oid=OiD,valueType=ValueType)
                ET.SubElement(Instance,'Value').text = Value
                print(' = '.join([x.prettyPrint() for x in varBind]))

        elif Exportileformat == '2':
            for varBind in varBinds:
                OiD = '.'.join([ str(x) for x in varBind[0]._ObjectIdentity__oid._value]) 
                Value = str(varBind[1].subtype().prettyPrint()).replace('\n',' ').replace('\r',' ').replace('\t',' ')
                ValueTypeID = varBind[1].subtype().prettyPrintType()
                ValueTypeID = str(ValueTypeID[str(ValueTypeID).index('tags ')+5:str(ValueTypeID).index('>')]).split(':')
                ValueTypeID = sum([int(x) for x in ValueTypeID])
                with open(f'{SwitchIP}.snmprec',mode='a') as f:
                    f.write(f'{OiD}|{ValueTypeID}|{Value}\n')
                print(' = '.join([x.prettyPrint() for x in varBind]))

if Exportileformat == '1':     
    data= ET.tostring( SnmpSimulatorData)
    dom = minidom.parseString(data)
    with open(f'{SwitchIP}.xml','w') as f:
        dom.writexml(f,'','\t','\n')