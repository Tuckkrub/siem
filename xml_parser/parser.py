import xml.etree.ElementTree as ET

tree = ET.parse('D:/work/2023-2/Thesis/siem/xml_parser/0250-apache_rules.xml')
root = tree.getroot()

print(root.tag)
print(root.attrib)
print(len(root))
print('=============================')

for i in range(len(root)):
    for j in range(len(root[i])):
        print(root[i][j].tag, '-> ', root[i][j].text)
    print('=============================')