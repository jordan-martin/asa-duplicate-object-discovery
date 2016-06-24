'''
Name: asa_duplicate_object.py
Description: Cisco ASA Firewall Duplicate Object Detection
Requires: Python 'sys', 'datetime' and 'ciscoconfparse' libraries

Usage:  asa_duplicate_object.py ''configuration_file_name'

'''

import sys
import datetime
from ciscoconfparse import CiscoConfParse

# Function to create dictionary of all objects and object-groups found in the configuration
def create_dict_object(input_raw,input_parse):
  objects = {}
  object_groups = {}
  for line in input_raw:
    # Identify network objects by matching the config line
    if 'object network' in line:
      # Find all child configurations components for this specific line
      object = input_parse.find_children_w_parents(line,'.*')
      # Isolate the name by popping it off the end of string
      name = (line.split()).pop(2)
      # We also need the first word in order to later ignore it if is a description
      first = (line.split()).pop(0)
      # Verify we haven't come across this object already and then create add it to the object 
      # dictionary with the child configuration provided as a list
      if not name in objects and first != "description":
        objects[name] = (object)
    # Repeating the above process but identifying object-groups instead
    if 'object-group network' in line:
      object_group = input_parse.find_children_w_parents(line,'.*')
      name = (line.split()).pop(2)
      first = (line.split()).pop(0)
      if not name in object_groups and first != "description":
        object_groups[name] = (object_group)
  # Return two dictionaries - one for objects and one for object groups
  return (objects,object_groups)

# This function identifies duplicate objects by iterating through the dictionary and looking
# for value matches
def check_dup_object(object_dictionary):
  duplicates = {}
  already_found = []
  #Yeah, I know the following is a hackers code...that's me.  Get the job done.  Fix it later.
  for k,v in object_dictionary.items():
    item = []
    # We don't want multiple iterations of the same matches - once an object has been processed
    # or found to be a duplicate, it is added to already_found and ignored in futer iterations
    if not k in already_found:
      for x,y in object_dictionary.items():
        # Looking to verify that the value from our source object matches the value of another
        # and both aren't empty
        if v == y and v and y:
          # Verify we haven't matched our own object name and then add the matched object name
          # to the list
          if k != x:
            item.append(x)
            if not x in already_found:
              already_found.append(x)
      already_found.append(k)
    # If we've matched - apply that match to the return dictionary
    if item:
      duplicates[k] = item
  # This should now be a dictionary with keys being an object and values being all of the matching
  # objects that were found.
  return (duplicates)

# This function identifies duplicate object groups by iterating through the dictionary and looking
# for value matches
def check_dup_object_group(object_group_dictionary):
  duplicates = {}
  already_found = []
  #Yeah, I know the following is a hackers code...that's me.  Get the job done.  Fix it later.
  for k,v in object_group_dictionary.items():
    item = []
    # We don't want multiple iterations of the same matches - once an object group has been processed
    # or found to be a duplicate, it is added to already_found and ignored in futer iterations
    if not k in already_found:
      for x,y in object_group_dictionary.items():
        # Looking to verify that the value from our source object group matches the value of another
        # and both aren't empty
        if v == y and v and y:
          # Verify we haven't matched our own object group name and then add the matched object name
          # to the list
          if k != x:
            item.append(x)
            if not x in already_found:
              already_found.append(x)
      already_found.append(k)
    # If we've matched - apply that match to the return dictionary
    if item:
      duplicates[k] = item
  # This should now be a dictionary with keys being an object group and values being all of the matching
  # object groups that were found.
  return (duplicates)


# This function is used to write detailed output to a file for future review
def write_to_file(objects,object_groups,input_parse):
  today = datetime.date.today()
  # Today the file name is hardcoded, future versions will include an optional output file name and possibly type
  f = open("output.txt",'w')
  f.write("Output For asa_duplicate_object\n")
  f.write("Date: " + today.ctime() + "\n")
  f.write("Input File:  " + sys.argv[1] + "\n\n\n")

  # Object Output

  f.write("------------------------------\n     Object Duplicates\n------------------------------\n\n\n")
  i = 1
  for k,v in objects.items():
    f.write("-----------------\nDuplicate Item " + str(i) + "\n-----------------\n\n")
    #Write primary object out
    f.write("First Object Found:\n\n")
    primary = input_parse.find_all_children('object network ' + k)
    for lines in primary:
      f.write("\t" + lines)
    f.write("\n\n")
    #Write ancillary objects out
    f.write("Identical Object(s):\n\n")
    for items in objects[k]:
      secondary = input_parse.find_all_children('object network ' + items)
      for sec in secondary:
        f.write("\t" + sec)
      f.write("\n")
    f.write("\n\n")
    #Write dependent configurations of primary
    f.write("Configuration Dependent On Primary Object:\n\n")
    depend_primary = input_parse.find_blocks(k)
    for dep_pri in depend_primary:
      f.write("\t" + dep_pri)
    f.write("\n\n")
    #Write dependent configurations of primary
    f.write("Configuration Dependent On Secondary Object(s):\n\n")
    for more_items in objects[k]:
      depend_secondary = input_parse.find_blocks(more_items)
      for dep_sec in depend_secondary:
        f.write("\t" + dep_sec)
    f.write("\n\n\n\n\n\n")
    i += 1
  f.write("\n\n\n\n\n\n")
  
  # Object Group Output

  f.write("------------------------------\n     Object Group Duplicates\n------------------------------\n\n\n")
  i = 1
  for k,v in object_groups.items():
    f.write("-----------------\nDuplicate Item " + str(i) + "\n-----------------\n\n")
    #Write primary object out
    f.write("First Object Group Found:\n\n")
    primary = input_parse.find_all_children('object-group network ' + k)
    for lines in primary:
      f.write("\t" + lines)
    f.write("\n\n")
    #Write ancillary objects out
    f.write("Identical Object Group(s):\n\n")
    for items in object_groups[k]:
      secondary = input_parse.find_all_children('object-group network ' + items)
      for sec in secondary:
        f.write("\t" + sec)
      f.write("\n")
    f.write("\n\n")
    #Write dependent configurations of primary
    f.write("Configuration Dependent On Primary Object Group:\n\n")
    depend_primary = input_parse.find_blocks(k)
    for dep_pri in depend_primary:
      f.write("\t" + dep_pri)
    f.write("\n\n")
    #Write dependent configurations of primary
    f.write("Configuration Dependent On Secondary Object Group(s):\n\n")
    for more_items in object_groups[k]:
      depend_secondary = input_parse.find_blocks(more_items)
      for dep_sec in depend_secondary:
        f.write("\t" + dep_sec)
    f.write("\n\n\n\n\n\n")
    i += 1
  f.write("\n\n\n\n\n\n")
  f.close()


# This function doesn't do anything, that's why I named it main.
def main():
  # Verify we have the right number of arguments.  Probably should write some else code in eventually
  if len(sys.argv) == 2:
    # This is our source config file, it's important.
    x = open(sys.argv[1])
    # Read the source file into a varaible for future use
    config_raw = x.readlines()
    # This is a parsed version of the config using CiscoConfParse, also very important
    config_parse = CiscoConfParse(config_raw) 
    x.close()

    # Real work starts - take the config and sent it off to be broken down into object and object group dictionaries
    object_dict, object_group_dict = create_dict_object(config_raw,config_parse)
    # Use the above dictionaries to see if we have duplicate objects or object groups
    object_dups = check_dup_object(object_dict)
    object_group_dups = check_dup_object_group(object_group_dict)
    # Share what we've learned with the output file
    write_to_file(object_dups,object_group_dups,config_parse)


if __name__ == '__main__':
  main()


# If you've made it this far I'm impressed.  I know I'm a hack of programmer but it does what I need it to.
# You should go grab a beer or something to lower your anxiety from reading this code.