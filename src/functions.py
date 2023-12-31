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

raster_tags = ['format','height','width','crs','spatial_coverage','spatial_resolution','start_date','end_date','temporal_resolution','no_data_value']

rdfgraph_tags = ['num_nodes','num_edges','num_namespaces','num_classes','num_object_properties','num_datatype_properties','density','num_connected_components']

hierarchical_tags = ['num_records', 'num_attributes']

text_tags = ['language','num_sentences','num_words','num_distinct_words','num_characters','ratio_uppercase','ratio_digits','ratio_special_characters']


# Properties regarding the various types of distributions

numerical_distribution_tags = ['count','average','stddev','min','max','median','percentile10','percentile25','percentile75','percentile90','kurtosis','skewness','variance']

categorical_distribution_tags = ['type','class_name','count','percentage']

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
        if isinstance(geometry, dict):
            return json.dumps(geometry)   # dictionary
        else:
            g = json.loads(geometry)      # string containing a JSON
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
        elif isinstance(value, list):  # Convert a list as required for extras in CKAN.
            item["value"] = json.dumps(value)
        else:
            item["value"] = value
        extras.append(item)
#    arr_json = json.dumps(extras)
    return extras


def handle_keywords(list_tags):
    """Convert a list of keywords from the input JSON into the format required for keywords (tags) in CKAN.

    Args:
        A JSON array with string values.

    Returns:
        A JSON array as required for keywords (tags) in CKAN.
    """

    tags = []
    for value in list_tags:
        item = {}
        item["name"] = value
        tags.append(item)

    return tags


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



def processTabularResource(resource_id, metadata, sql):
    """Process metadata about a tabular resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the the metadata of this tabular resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    tabular_metadata = cleanupDict(copy.deepcopy(prof), tabular_tags)         
    tabular_metadata['resource_id'] = resource_id
    # Rename property as required by the schema
    if 'num_columns' in tabular_metadata:
        tabular_metadata['num_columns'] = tabular_metadata.pop('num_attributes')
    sql.append(prepareInsertSql(tabular_metadata, 'klms.tabular'))



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


def processRasterResource(resource_id, metadata, sql):
    """Process metadata regarding a raster resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the metadata of this raster resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    raster_metadata = cleanupDict(copy.deepcopy(metadata), raster_tags)     
    raster_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(raster_metadata, 'klms.raster'))


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


def processHierarchicalResource(resource_id, metadata, sql):
    """Process metadata about a hierarchical resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the the metadata of this hierarchical resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    hierarchical_metadata = cleanupDict(copy.deepcopy(prof), hierarchical_tags)         
    hierarchical_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(hierarchical_metadata, 'klms.hierarchical'))


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


def processRdfGraphResource(resource_id, metadata, sql):
    """Process metadata about a RDF graph resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the the metadata of this RDF graph resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    rdfgraph_metadata = cleanupDict(copy.deepcopy(prof), rdfgraph_tags)         
    rdfgraph_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(rdfgraph_metadata, 'klms.rdfgraph'))



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
            # Rename property as required by the schema
            item['type'] = item.pop('class_name')
            sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
        rdfgraph_metadata['class_distribution'] = class_uuid
    # Must have included foreign keys to the various distributions
    sql.append(prepareInsertSql(rdfgraph_metadata, 'klms.rdfgraph'))



def processTextualResource(resource_id, metadata, sql):
    """Process metadata about a textual resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the the metadata of this textual resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    text_metadata = cleanupDict(copy.deepcopy(prof), text_tags)         
    text_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(text_metadata, 'klms.text'))



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



def extractResourceProperties(resource_id, metadata):
    """Provides metadata extracted from a resource that conform to the KLMS schema.

    Args:
        resource_id (String) : A unique identifier for this resource.
        metadata (dict): JSON containing the resource metadata.

    Returns:
        A collection of INSERT SQL statements to be executed for ingesting resource metadata into PostgreSQL according to KLMS schema.
    """

    sql = []   		# Collects SQL commands to be executed

    # PHASE #1: Dataset-related information
    # Handle each resource according to its type
    if metadata['resource_type'] == 'Tabular':
        processTabularResource(resource_id, metadata, sql)
        return sql
    elif metadata['resource_type'] == 'Raster':
        processRasterResource(resource_id, metadata, sql)
        return sql
    elif metadata['resource_type'] == 'Hierarchical':
        processHierarchicalResource(resource_id, metadata, sql)
        return sql
    elif metadata['resource_type'] == 'RDFGraph':
        processRdfGraphResource(resource_id, metadata, sql)
        return sql
    elif metadata['resource_type'] == 'Textual':
        processTextualResource(resource_id, metadata, sql)
        return sql

    #TODO: Vector ???
    #TODO: TimeSeries ???

    # PHASE #2: Attribute-related information NOT applicable

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


def prepareZenodoMetadata(dataset, creator, creator_org, doi:None):
    """Prepares the metadata in JSON about a dataset as expected by Zenodo.

    Args:
        dataset (JSON): A JSON object representing metadata for a dataset (CKAN packege).
        creator (String): The name of the creator of the dataset as listed in CKAN.
        creator_org (String): The name of the owner organization of the dataset as listed in CKAN.
        doi (String): The Digital Object Identifier of the dataset, if already assigned by the publisher If not, leave the field empty and Zenodo will register a new DOI when the dataset gets published.

    Returns:
        A JSON as expected by Zenodo for describing a dataset.
    """

    # Extract specific metadata as required by Zenodo schema 
    # (schema largely conforms with https://schema.datacite.org/meta/kernel-4.4/metadata.xsd)
    res_id = dataset['id']
    
    # Basic metadata
    title = dataset['title']
    description = dataset['notes']
    tags = [t['name'] for t in dataset['tags']]
    
    # List of creators/authors of the Zenodo deposition (dataset)
    author = dataset['author'] if dataset['author'] else None
    maintainer = dataset['maintainer'] if dataset['maintainer'] else None
    organization = dataset['organization']['description']
    creators = []
    if creator:
        creators.append({'name': creator, 'affiliation': creator_org})
    if author:
        creators.append({'name': author, 'affiliation': organization})
    if maintainer:
        creators.append({'name': maintainer, 'affiliation': organization})

    url = dataset['url'] if dataset['url'] else None
    version = dataset['version'] if dataset['version'] else None
    isopen = dataset['isopen']
    private = dataset['private']
    license_title = dataset['license_title'] if dataset['license_title'] else None

    # Handle some of the available extra metadata
    spatial = next((item['value'] for item in dataset['extras'] if item['key'] == 'spatial'), None)
    spatial_resolution_in_meters = next((item['value'] for item in dataset['extras'] if item['key'] == 'spatial_resolution_in_meters'), None)
    temporal_start = next((item['value'] for item in dataset['extras'] if item['key'] == 'temporal_start'), None)
    temporal_end = next((item['value'] for item in dataset['extras'] if item['key'] == 'temporal_end'), None)
    frequency = next((item['value'] for item in dataset['extras'] if item['key'] == 'frequency'), None)
    documentation = next((item['value'] for item in dataset['extras'] if item['key'] == 'documentation'), None)
    language = next((item['value'] for item in dataset['extras'] if item['key'] == 'language'), None)
    theme = next((item['value'] for item in dataset['extras'] if item['key'] == 'theme'), None)
    alternate_identifier = next((item['value'] for item in dataset['extras'] if item['key'] == 'alternate_identifier'), None)

    # locations : list of locations -> NOT always the BBOX specified in CKAN
    # * lat (double): latitude
    # * lon (double): longitude
    # * place (string): place�s name (required)
    # * description (string): place�s description (optional)
    # Example: [{"lat": 34.02577, "lon": -118.7804, "place": "Los Angeles"}, {"place": "Mt.Fuji, Japan", "description": "Sample found 100ft from the foot of the mountain."}]
    locations = None
    if spatial:
        locations = []
        loc = {}
        # Extract the centroid from the spatial extent in CKAN
        geom = json.loads(spatial) 
        bbox = shape(geom)
        loc['lon'] = bbox.centroid.x
        loc['lat'] = bbox.centroid.y
        loc['place'] = 'N/A'
        locations.append(loc)

    # access_right -> Controlled vocabulary in Zenodo:
    # * open: Open Access
    # * embargoed: Embargoed Access
    # * restricted: Restricted Access
    # * closed: Closed Access
    if isopen:
        access_right = "open"
        license = license_title if license_title else None
    elif private:
        access_right = "closed"
    else:
        access_right = "restricted"

    # dates -> List of date intervals
    # * start (ISO date string): start date (*)
    # * end (ISO date string): end date (*)
    # * type (Collected, Valid, Withdrawn): The interval�s type (required)
    # * description (string): The interval�s description (optional)
    # (*) Note that you have to specify at least a start or end date. For an exact date, use the same value for both start and end.
    # Example: [{"start": "2018-03-21", "end": "2018-03-25", "type": "Collected", "description": "Specimen A5 collection period."}]
    dates = None
    if temporal_start or temporal_end:
        dates = []
        timespan = {'type' : 'Valid'}   # Assuming that timespan specified the time period when dataset is valid
        if temporal_start:
            timespan['start'] = temporal_start
        if temporal_end:
            timespan['end'] = emporal_end
        dates.append(timespan)

    # language: the main language of the record as ISO 639-2 or 639-3 code
    lang = None
    if language:
        list_lang = language.replace('{','').replace('}','').split(',')  
        lang = list_lang[0]  # the first language specified in CKAN

    # https://developers.zenodo.org/#representation
    # IMPORTANT: By default, using EU project grant for STELAR. List of OpenAIRE-supported grants. Example: [{'id':'283595'}] (European Commission grants only) or funder DOI-prefixed: [{'id': '10.13039/501100000780::283595'}] (All grants, recommended)
    zenodo_metadata = { "upload_type":"dataset", "creators": creators, "title": title, "description": description, "keywords": tags, "access_right": access_right, "language":lang, "locations": locations, "dates" : dates,"license": license,"doi": doi, "grants": [{"id": "10.13039/501100000780::101070122"}] }

    return zenodo_metadata


