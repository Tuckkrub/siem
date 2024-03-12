import xml.etree.ElementTree as ET

tree = ET.parse('D:/work/2023-2/Thesis/siem/xml_parser/0250-apache_rules.xml')
root = tree.getroot()

print(root.tag)
print(root.attrib)
print(len(root))
print('=============================')

for i in range(len(root)):
    for j in range(len(root[i])):
        if root[i][j].tag == 'id':
            error_id = root[i][j].text.split('|')
            for entity in error_id:
                print(root[i][j+1].text, ': ', 'col("entity")==', entity)
    print('=============================')



# "Forbidden Directory Access_denied": (col("entity")=="AH01276"),
