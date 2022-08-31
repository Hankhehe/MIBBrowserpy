from pysnmp.hlapi import *
import xml.etree.cElementTree as ET
from xml.dom import minidom

while True:
    DefaultOID = input('default OID ex .1.3 : ')
    SwitchIP = input('Switch IP :')
    CommunityString = input('Community String :')
    SNMPVersion = input('SNMP Version ex 1 or 2 : ')
    if not DefaultOID :
        print('vaule is null')
    else:
        break

SnmpSimulatorData = ET.Element('SnmpSimulatorData')
Instances = ET.SubElement(SnmpSimulatorData, 'Instances')
iterator = nextCmd(
    SnmpEngine(),
    CommunityData(CommunityString, mpModel=int(SNMPVersion) - 1),
    UdpTransportTarget((SwitchIP, 161)),
    ContextData(),
    ObjectType(ObjectIdentity(DefaultOID))
)
for errorIndication, errorStatus, errorIndex, varBinds in iterator:

    if errorIndication:
        print(errorIndication)
        break

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        break

    else:
        for varBind in varBinds:
            OidName = varBind[0]._ObjectIdentity__symName
            OiD = '.'+'.'.join([ str(x) for x in varBind[0]._ObjectIdentity__oid._value]) 
            Value = varBind[1].prettyPrint()
            Instance = ET.SubElement(Instances, 'Instance', name=OidName,oid=OiD,valueType='OctetString')
            ET.SubElement(Instance,'Value').text = Value
            print(' = '.join([x.prettyPrint() for x in varBind]))
data= ET.tostring( SnmpSimulatorData)
dom = minidom.parseString(data)
with open(f'{SwitchIP}.xml','w') as f:
    dom.writexml(f,'','\t','\n')