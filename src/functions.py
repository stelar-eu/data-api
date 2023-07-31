import flask
import requests
import json
import re
import psycopg2
import uuid
import copy

from flask import request, jsonify
from requests.auth import HTTPBasicAuth
import urllib.parse
from shapely.geometry import shape, GeometryCollection
import shapely.wkt



# Properties regarding the various types of attributes to be extracted from profiles 

attribute_tags = ['type','count','num_missing','theme','uniqueness','nesting_level']

series_tags = ['num_peaks','abs_energy','abs_sum_changes','len_above_mean','len_below_mean']

temporal_tags = ['start','end']

geometry_tags = ['mbr','centroid','crs']

textual_tags = ['ratio_uppercase','ratio_digits','ratio_special_characters']


# Properties regarding entire profiles

tabular_tags = ['num_rows','num_attributes']

raster_tags = ['format','height','width','crs','spatial_coverage','spatial_resolution','temporal_coverage','temporal_resolution','no_data_value']

rdfgraph_tags = ['num_nodes','num_edges','num_namespaces','num_classes','num_object_properties','num_datatype_properties','density','num_connected_components']

hierarchical_tags = ['num_records', 'num_attributes']

text_tags = ['language','num_sentences','num_words','num_distinct_words','num_characters','ratio_uppercase','ratio_digits','ratio_special_characters']


# Properties regarding the various types of distributions

numerical_distribution_tags = ['count','average','stddev','min','max','median','percentile10','percentile25','percentile75','percentile90','kurtosis','skewness','variance']

categorical_distribution_tags = ['type','count','percentage']

language_distribution_tags = ['language','percentage']



def create_CKAN_headers(API_TOKEN):
    """Create the headers required for publishing a package or a resource in CKAN.

    Args:
        API_TOKEN (string): The API_TOKEN issued by CKAN that is required to establish connection and submit the request.

    Returns:
        Two JSON obejcts: (i) headers for package and (ii) headers for resource.
    """

    package_headers = {'Authorization': API_TOKEN, 'Content-Type': 'application/json'}
    resource_headers = { 'X-CKAN-API-Key': API_TOKEN }
    return package_headers, resource_headers


def validate_spatial(geometry):
    """Prepares the value for spatial extent in GeoJSON as expected by CKAN.

    Args:
        geometry: A WKT string or GeoJSON object representing a 2-dimensional geometry.

    Returns:
        A GeoJSON as expected by CKAN for spatial indexing in SOLR.
    """
    
    try:  # First, consider it as a GeoJSON
        g = json.loads(geometry)
    except:   
        try:  # Then, assuming this is WKT
            wkt = shapely.wkt.loads(geometry)
            g = shapely.geometry.mapping(wkt)
        except: 
            g = {"type":"Polygon","coordinates":[]}  # Empty polygon
    
    return json.dumps(g)


def calc_bbox(geometry):
    """Calculate the bounding box of a geometry.

    Args:
        geometry: A GeoJSON object representing a 2-dimensional geometry.

    Returns:
        A list of four coordinates representing a bounding box (left, bottom, right, top).
    """

#    print("GeoJSON:", geometry)
    # NOTE: buffer(0) is a trick for fixing scenarios where polygons have overlapping coordinates 
    g = GeometryCollection([shape(geometry).buffer(0)])
    bbox = g.bounds

    return str(bbox[0])+","+str(bbox[1])+","+str(bbox[2])+","+str(bbox[3])


def handle_extras(json_metadata):
    """Convert key value pairs from the input JSON into the format required for extra metadata in CKAN.

    Args:
        A JSON object with key value pairs.

    Returns:
        A JSON array as required for extra metadata in CKAN.
    """

    extras = []
    for key,value in json_metadata.items():
        item = {}
        item["key"] = key 
        if key=="spatial": # Special handling of GeoJSON or WKT for spatial extent
            item["value"] = validate_spatial(json_metadata['spatial'])   #json.dumps(json_metadata['spatial'])
        else:
            item["value"] = value
        extras.append(item)
#    arr_json = json.dumps(extras)
    return extras


def format_CKAN_filter(json_metadata):
    """Convert key value pairs from the input JSON into the format required for queries in CKAN by SOLR. SOLR syntax: https://gist.github.com/mankyKitty/5906859

    Args:
        json_metadata (dict): A JSON object with key value pairs.

    Returns:
        A string with the query specifications for submission to CKAN.
    """

    q = '?q='
    bbox = None
    for key,value in json_metadata.items():
        if key=="spatial": # Special handling of GeoJSON 
            bbox = calc_bbox(value) # Replace given GeoJSON with its BBOX
#            print("bbox: " , bbox)            
    if bbox:
#        json_metadata['ext_bbox'] = bbox
        ext_bbox = 'ext_bbox='+urllib.parse.quote(bbox)
        del json_metadata['spatial']  # Remove GeoJSON from the parameters
    else:
        ext_bbox = None

    # Encode parameters for the URL request, as required by SOLR
    filters = urllib.parse.urlencode(json_metadata, doseq=False)

    if filters:
        q += urllib.parse.quote(filters)

    if ext_bbox:
        q = '?' + ext_bbox

#        if q:
#            q += '&' + ext_bbox
#        else:
#            q = '?' + ext_bbox

    return q   #urllib.parse.quote(q) #.encode('iso-8859-1'))


def cleanupDict(mydict, keys):
    """Removes any elements in the given dictionary that are not tagged under the given keys.

    Args:
        mydict (dict): A dictionary with key value pairs.
        keys (list): List of keys to retain in the given dictionary.

    Returns:
        A copy of the input dictionary, holding only the specified keys (if present).
    """

    for k in mydict.copy().keys():
        if not k in keys:
            mydict.pop(k) # Does nothing if the key is not present
            
    return mydict


def cleanupListDict(mylist, keys):
    """Removes any elements in each dictionary in the given list that are not tagged under the given keys.

    Args:
        mylist (dict): A list of dictionaries, each with the same key value pairs.
        keys (list): List of keys to retain in each dictionary.

    Returns:
        A copy of the input list, holding only the specified keys (if present) in each dictionary.
    """

    newlist = []
    for d in mylist:
        newlist.append(cleanupDict(d, keys))
            
    return newlist



def processTabularProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of a tabular/vector dataset.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this profile
    tabular_metadata = cleanupDict(copy.deepcopy(prof), tabular_tags)         
    tabular_metadata['resource_id'] = resource_id
    # Rename property as required by the schema
    tabular_metadata['num_columns'] = tabular_metadata.pop('num_attributes')
    sql.append(prepareInsertSql(tabular_metadata, 'klms.tabular'))



def processRasterProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of a raster dataset.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this profile
    raster_metadata = cleanupDict(copy.deepcopy(prof), raster_tags)   
    # CAUTION! Currently, a raster profile indicates spatial resolution per axis; KLMS schema assumes a common resolution
    raster_metadata['spatial_resolution'] = raster_metadata['spatial_resolution']['pixel_size_x']      
    raster_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(raster_metadata, 'klms.raster'))

    # Also ingest information about each of the bands
    for band in prof['bands']:
        # Numerical distribution of pixel values 
        band_distribution = cleanupDict(copy.deepcopy(band), numerical_distribution_tags)   
        band_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
        sql.append(prepareInsertSql(band_distribution, 'klms.numerical_distribution'))
        # Also handle this band as a numerical attribute
        attr_metadata = {}         
        attr_metadata['attr_name'] = band['name']
        attr_metadata['type'] = 'Band'
        attr_metadata['attr_id'] = band['uuid']  # Reuse the UUID already included in the original profile
        attr_metadata['resource_id'] = resource_id
        sql.append(prepareInsertSql(attr_metadata, 'klms.attribute'))
        band_metadata = {}
        band_metadata['attr_id'] = band['uuid']  # Reuse the UUID already included in the original profile
        band_metadata['value_distribution'] = band_distribution['distr_id']
        sql.append(prepareInsertSql(band_metadata, 'klms.numerical_attribute'))


def processHierarchicalProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of a hierarchical dataset.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Get all values concerning depth distribution
    depth_distribution = cleanupDict(copy.deepcopy(prof['depth_distribution']), numerical_distribution_tags)   
    depth_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
    sql.append(prepareInsertSql(depth_distribution, 'klms.numerical_distribution'))
    # Collect general info about this profile
    hierarchical_metadata = cleanupDict(copy.deepcopy(prof), hierarchical_tags)         
    hierarchical_metadata['resource_id'] = resource_id
#    hierarchical_metadata['num_attributes'] = len(profile['variables'])   # CAUTION! property NOT currently available in the profile
    hierarchical_metadata['depth_distribution'] = depth_distribution['distr_id']
    sql.append(prepareInsertSql(hierarchical_metadata, 'klms.hierarchical'))



def processRdfGraphProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of an RDF graph.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this profile
    rdfgraph_metadata = cleanupDict(copy.deepcopy(prof), rdfgraph_tags)         
    rdfgraph_metadata['resource_id'] = resource_id

    # Also get all statistics concerning its various distributions
    degree_centrality_distribution = cleanupDict(copy.deepcopy(prof['degree_centrality_distribution']), numerical_distribution_tags)   
    degree_centrality_distribution['distr_id'] = str(uuid.uuid1())  # Generate a UUID for this distribution
    rdfgraph_metadata['degree_centrality_distribution'] = degree_centrality_distribution['distr_id']
    sql.append(prepareInsertSql(degree_centrality_distribution, 'klms.numerical_distribution'))
    degree_distribution = cleanupDict(copy.deepcopy(prof['degree_distribution']), numerical_distribution_tags)   
    degree_distribution['distr_id'] = str(uuid.uuid1())  # Generate a UUID for this distribution
    rdfgraph_metadata['degree_distribution'] = degree_distribution['distr_id']
    sql.append(prepareInsertSql(degree_distribution, 'klms.numerical_distribution'))
    in_degree_distribution = cleanupDict(copy.deepcopy(prof['in_degree_distribution']), numerical_distribution_tags)   
    in_degree_distribution['distr_id'] = str(uuid.uuid1())  # Generate a UUID for this distribution
    rdfgraph_metadata['in_degree_distribution'] = in_degree_distribution['distr_id']
    sql.append(prepareInsertSql(in_degree_distribution, 'klms.numerical_distribution'))
    out_degree_distribution = cleanupDict(copy.deepcopy(prof['out_degree_distribution']), numerical_distribution_tags)   
    out_degree_distribution['distr_id'] = str(uuid.uuid1())  # Generate a UUID for this distribution
    rdfgraph_metadata['out_degree_distribution'] = out_degree_distribution['distr_id']
    sql.append(prepareInsertSql(out_degree_distribution, 'klms.numerical_distribution'))
    if 'class_distribution' in prof:
        class_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
        class_distribution = cleanupListDict(copy.deepcopy(prof['class_distribution']), categorical_distribution_tags)
        for item in class_distribution:
            item['distr_id'] = class_uuid
            sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
        rdfgraph_metadata['class_distribution'] = class_uuid
    # Must have included foreign keys to the various distributions
    sql.append(prepareInsertSql(rdfgraph_metadata, 'klms.rdfgraph'))




def processTextualProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of a text.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this profile
    text_metadata = cleanupDict(copy.deepcopy(prof), text_tags)         
    text_metadata['resource_id'] = resource_id
    # Get all values concerning its various distributions
    if 'sentence_length_distribution' in prof:
        sentence_length_distribution = cleanupDict(copy.deepcopy(prof['sentence_length_distribution']), numerical_distribution_tags)   
        sentence_length_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
        sql.append(prepareInsertSql(sentence_length_distribution, 'klms.numerical_distribution'))
        text_metadata['sentence_length_distribution'] = sentence_length_distribution['distr_id']
    if 'word_length_distribution' in prof:
        word_length_distribution = cleanupDict(copy.deepcopy(prof['word_length_distribution']), numerical_distribution_tags)   
        word_length_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
        sql.append(prepareInsertSql(word_length_distribution, 'klms.numerical_distribution'))
        text_metadata['word_length_distribution'] = word_length_distribution['distr_id']
    if 'language_distribution' in prof:
        lang_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
        lang_distribution = cleanupListDict(copy.deepcopy(prof['language_distribution']), language_distribution_tags)
        for item in lang_distribution:
            item['distr_id'] = lang_uuid
            # Rename property as required by the schema
            item['type'] = item.pop('language')
            sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
        text_metadata['language_distribution'] = lang_uuid
    if 'special_characters_distribution' in prof:
        chars_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
        chars_distribution = cleanupListDict(copy.deepcopy(prof['special_characters_distribution']), categorical_distribution_tags)
        for item in chars_distribution:
            item['distr_id'] = chars_uuid
            sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
        text_metadata['special_characters_distribution'] = chars_uuid
    # Must have included foreign keys to the various distributions
    sql.append(prepareInsertSql(text_metadata, 'klms.text'))


def extractProfileProperties(resource_id, profile):
    """Provides metadata extracted from a data profile.

    Args:
        resource_id (String) : A unique identifier for this profile.
        profile (array): JSON array containing the profile information.

    Returns:
        A collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    sql = []   		# Collects SQL commands to be executed

    # PHASE #1: Dataset-related information
    prof = profile['table']  # No need to generate a UUID for this dataset; it has already obtained one as a CKAN resource
    # Handle each profile according to its type
    if prof['profiler_type'] == 'Tabular':
        processTabularProfile(resource_id, prof, sql)
    elif prof['profiler_type'] == 'Raster':
        # IMPORTANT! Extract information about the first raster in the collection (the only one allowed in CKAN)
        if len(profile['variables']) > 0:
            processRasterProfile(resource_id, profile['variables'][0], sql)
            # IMPORTANT! Return the list of collected SQL commands for execution
            return sql
    elif prof['profiler_type'] == 'Hierarchical':
        processHierarchicalProfile(resource_id, prof, sql)
    elif prof['profiler_type'] == 'RDFGraph':
        processRdfGraphProfile(resource_id, prof, sql)
        # IMPORTANT! Return the list of collected SQL commands for execution
        return sql
    elif prof['profiler_type'] == 'Textual':
        # TODO: Textual profiling is applicable on text collections; but CKAN accepts each text file as a separate resource
        # OPTION #1: Extract information about the corpus
        #processTextualProfile(resource_id, prof, sql)
        # OPTION #2: Extract information about the first text in the corpus (the only one allowed in CKAN)
        if len(profile['variables']) > 0:
            processTextualProfile(resource_id, profile['variables'][0], sql)
            # IMPORTANT! Return the list of collected SQL commands for execution
            return sql

    # PHASE #2: Attribute-related information, value distributions
    for var in profile['variables']:
        # Generate a UUID for this attribute
        attr_uuid = str(uuid.uuid1())
        
        # Collect general info about this attribute
        attribute_metadata = cleanupDict(copy.deepcopy(var), attribute_tags)         
        attribute_metadata['attr_name'] = var['name']
        attribute_metadata['attr_id'] = attr_uuid
        attribute_metadata['resource_id'] = resource_id
        sql.append(prepareInsertSql(attribute_metadata, 'klms.attribute'))

        # Handle each attribute according to its type
        if var['type'] == 'Numeric':
            # Get all values concerning numerical distribution
            numerical_distribution = cleanupDict(copy.deepcopy(var), numerical_distribution_tags)   
#            numerical_distribution['attr_id'] = attr_uuid
            numerical_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
            sql.append(prepareInsertSql(numerical_distribution, 'klms.numerical_distribution'))
            # Compose values concerning the numerical attribute
            numerical_attribute = {} 
            numerical_attribute['attr_id'] = attr_uuid
            numerical_attribute['value_distribution'] = numerical_distribution['distr_id']
            sql.append(prepareInsertSql(numerical_attribute, 'klms.numerical_attribute'))
        elif var['type'] == 'TimeSeries':
            # Get all values concerning numerical distribution
            numerical_distribution = cleanupDict(copy.deepcopy(var), numerical_distribution_tags)   
#            numerical_distribution['attr_id'] = attr_uuid
            numerical_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
            sql.append(prepareInsertSql(numerical_distribution, 'klms.numerical_distribution'))
            # Get all values concerning time series statistics
            series_attribute = cleanupDict(copy.deepcopy(var), series_tags) 
            series_attribute['attr_id'] = attr_uuid
            series_attribute['value_distribution'] = numerical_distribution['distr_id']
            sql.append(prepareInsertSql(series_attribute, 'klms.series_attribute'))
        elif var['type'] == 'DateTime':
            # Get all values concerning a temporal attribute
            temporal_attribute = cleanupDict(copy.deepcopy(var), temporal_tags)
            temporal_attribute['attr_id'] = attr_uuid
            # Rename properties with PostgreSQL-reserved words
            temporal_attribute['start_time'] = temporal_attribute.pop('start')
            temporal_attribute['end_time'] = temporal_attribute.pop('end')
            sql.append(prepareInsertSql(temporal_attribute, 'klms.temporal_attribute'))
        elif var['type'] == 'Categorical':
            # Get all values concerning frequency distribution
            freq_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
            frequency_distribution = cleanupListDict(copy.deepcopy(var['frequency_distribution']), categorical_distribution_tags)   
            for item in frequency_distribution:
                item['distr_id'] = freq_uuid
#                item['attr_id'] = attr_uuid
                sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
            # Get all values concerning a categorical attribute
            categorical_attribute = {}
            categorical_attribute['attr_id'] = attr_uuid
            categorical_attribute['frequency_distribution'] = freq_uuid
            sql.append(prepareInsertSql(categorical_attribute, 'klms.categorical_attribute'))
        elif var['type'] == 'Textual':
            # Get all values concerning a textual attribute
            textual_attribute = cleanupDict(copy.deepcopy(var), textual_tags)
            textual_attribute['attr_id'] = attr_uuid
            # Collect any statistics about distributions
            if 'num_chars_distribution' in var:
                chars_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                chars_distribution = cleanupDict(copy.deepcopy(var['num_chars_distribution']), numerical_distribution_tags)
                chars_distribution['distr_id'] = chars_uuid
#                chars_distribution['attr_id'] = attr_uuid
                textual_attribute['num_chars_distribution'] = chars_uuid
                sql.append(prepareInsertSql(chars_distribution, 'klms.numerical_distribution'))
            if 'num_words_distribution' in var:
                words_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                words_distribution = cleanupDict(copy.deepcopy(var['num_words_distribution']), numerical_distribution_tags)
                words_distribution['distr_id'] = words_uuid
#                words_distribution['attr_id'] = attr_uuid
                textual_attribute['num_words_distribution'] = words_uuid
                sql.append(prepareInsertSql(words_distribution, 'klms.numerical_distribution'))
            # Must have included foreign keys to the various distributions
            sql.append(prepareInsertSql(textual_attribute, 'klms.textual_attribute'))
        elif var['type'] == 'Geometry':
            # Get all values concerning a geometry attribute
            geometry_attribute = cleanupDict(copy.deepcopy(var), geometry_tags)
            geometry_attribute['attr_id'] = attr_uuid
            # Collect any statistics about distributions
            if 'length_distribution' in var:
                length_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                length_distribution = cleanupDict(copy.deepcopy(var['length_distribution']), numerical_distribution_tags)
                length_distribution['distr_id'] = length_uuid
#                length_distribution['attr_id'] = attr_uuid
                geometry_attribute['length_distribution'] = length_uuid
                sql.append(prepareInsertSql(length_distribution, 'klms.numerical_distribution'))
            if 'area_distribution' in var:
                area_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                area_distribution = cleanupDict(copy.deepcopy(var['length_distribution']), numerical_distribution_tags)
                area_distribution['distr_id'] = area_uuid
#                area_distribution['attr_id'] = attr_uuid
                geometry_attribute['area_distribution'] = area_uuid
                sql.append(prepareInsertSql(area_distribution, 'klms.numerical_distribution'))
            if 'geom_type_distribution' in var:
                geomtype_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                geom_type_distribution = cleanupListDict(copy.deepcopy(var['geom_type_distribution']), categorical_distribution_tags)
                for item in geom_type_distribution:
                    item['distr_id'] = geomtype_uuid
#                    item['attr_id'] = attr_uuid
                    sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
                geometry_attribute['geom_type_distribution'] = geomtype_uuid
            # Must have included foreign keys to the various distributions
            sql.append(prepareInsertSql(geometry_attribute, 'klms.geometry_attribute'))

    # Return the list of collected SQL commands for execution
    return sql



def prepareInsertSql(metadata, table):
    """Prepares an INSERT statement in SQL for ingesting the metadata into the specified table.

    Args:
#        resource_id (String): The name of the table where this data will be inserted.
        table (String): The name of the table where this data will be inserted.
        metadata (dict): JSON dictionary containing key, value pairs.

    Returns:
        A string with the INSERT statement to be executed in PostgreSQL.
    """

    columns = ", ".join(list(metadata.keys()))
    values = ", ".join("'{0}'".format(item) for item in metadata.values())
    sql = "INSERT INTO " + table + "(" + columns + ")" + " VALUES (" + values + ");"

    return sql


