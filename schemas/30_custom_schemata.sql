-- ***************************************

-- Create PostGIS extension required for geospatial data management

CREATE EXTENSION IF NOT EXISTS postgis;


--****************************************************************
--           Custom schema for WORKFLOW & TASK EXECUTIONS
--****************************************************************

CREATE SCHEMA klms;

-- Execution states for workflows & tasks

-- DROP TYPE state_enum;

CREATE TYPE state_enum AS ENUM ('created', 'restarting', 'running', 'removing', 'paused',  'dead', 'succeeded', 'failed');


---------------------------------------------
--           WORKFLOW EXECUTIONS
---------------------------------------------

-- DROP TABLE klms.workflow_execution;

CREATE TABLE klms.workflow_execution
( workflow_uuid varchar(64) NOT NULL,
  "state" state_enum NOT NULL, 
  start_date timestamp,
  end_date timestamp,
--  package_id text,
  PRIMARY KEY (workflow_uuid)
--,  CONSTRAINT fk_workflow_id FOREIGN KEY(package_id) REFERENCES public.package(id) ON UPDATE CASCADE ON DELETE CASCADE
);


-- DROP TABLE klms.workflow_tag;

CREATE TABLE klms.workflow_tag
( workflow_uuid varchar(64) NOT NULL,
  "key" text NOT NULL, 
  "value" text,
  PRIMARY KEY (workflow_uuid, "key"),
  CONSTRAINT fk_workflow_tag_uuid FOREIGN KEY(workflow_uuid) REFERENCES klms.workflow_execution(workflow_uuid) ON UPDATE CASCADE ON DELETE CASCADE
);

-- Index key value pairs for faster search:

CREATE INDEX klms_workflow_tag_idx_key ON klms.workflow_tag(key);
CREATE INDEX klms_workflow_tag_idx_value ON klms.workflow_tag(value);

---------------------------------------------
--           TASK EXECUTIONS
---------------------------------------------

-- DROP TABLE klms.task_execution;

CREATE TABLE klms.task_execution
( task_uuid varchar(64) NOT NULL,
  workflow_uuid varchar(64) NOT NULL,
  "state" state_enum NOT NULL, 
  start_date timestamp,
  end_date timestamp,
  next_task_uuid varchar(64),
  PRIMARY KEY (task_uuid),
  CONSTRAINT fk_workflow_uuid FOREIGN KEY(workflow_uuid) REFERENCES klms.workflow_execution(workflow_uuid) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_next_task_uuid FOREIGN KEY(next_task_uuid) REFERENCES klms.task_execution(task_uuid) ON UPDATE CASCADE ON DELETE SET NULL
);


-- DROP TABLE klms.task_tag;

CREATE TABLE klms.task_tag
( task_uuid varchar(64) NOT NULL,
  "key" text NOT NULL, 
  "value" text,
  PRIMARY KEY (task_uuid, "key"),
  CONSTRAINT fk_task_tag_uuid FOREIGN KEY(task_uuid) REFERENCES klms.task_execution(task_uuid) ON UPDATE CASCADE ON DELETE CASCADE
);

-- Index key value pairs for faster search:

CREATE INDEX klms_task_tag_idx_key ON klms.task_tag(key);
CREATE INDEX klms_task_tag_idx_value ON klms.task_tag(value);


-- DROP TABLE klms.metrics;

CREATE TABLE klms.metrics
( task_uuid varchar(64) NOT NULL,
  "key" text NOT NULL, 
  "value" text,
  issued timestamp,
  PRIMARY KEY (task_uuid, "key", issued),
  CONSTRAINT fk_task_metrics_uuid FOREIGN KEY(task_uuid) REFERENCES klms.task_execution(task_uuid) ON UPDATE CASCADE ON DELETE CASCADE
);

-- Index key value pairs for faster search:

CREATE INDEX klms_metrics_idx_key ON klms.metrics(key);
CREATE INDEX klms_metrics_idx_value ON klms.metrics(value);


-- DROP TABLE klms.parameters;

CREATE TABLE klms.parameters
( task_uuid varchar(64) NOT NULL,
  "key" text NOT NULL, 
  "value" text,
  PRIMARY KEY (task_uuid, "key"),
  CONSTRAINT fk_task_parameters_uuid FOREIGN KEY(task_uuid) REFERENCES klms.task_execution(task_uuid) ON UPDATE CASCADE ON DELETE CASCADE
);

-- Index key value pairs for faster search:

CREATE INDEX klms_parameters_idx_key ON klms.parameters(key);
CREATE INDEX klms_parameters_idx_value ON klms.parameters(value);


-- DROP TABLE klms.task_input;

CREATE TABLE klms.task_input
( task_uuid varchar(64) NOT NULL,
  order_num smallint,
  dataset_id text NOT NULL, 
  PRIMARY KEY (task_uuid, dataset_id),
  CONSTRAINT fk_task_input_uuid FOREIGN KEY(task_uuid) REFERENCES klms.task_execution(task_uuid) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_task_input_dataset FOREIGN KEY(dataset_id) REFERENCES public.resource(id) ON UPDATE CASCADE ON DELETE CASCADE
);


-- DROP TABLE klms.task_output;

CREATE TABLE klms.task_output
( task_uuid varchar(64) NOT NULL,
  order_num smallint,
  dataset_id text NOT NULL, 
  PRIMARY KEY (task_uuid, dataset_id),
  CONSTRAINT fk_task_output_uuid FOREIGN KEY(task_uuid) REFERENCES klms.task_execution(task_uuid) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_task_output_dataset FOREIGN KEY(dataset_id) REFERENCES public.resource(id) ON UPDATE CASCADE ON DELETE CASCADE
);


-- ***************************************

-----------------------------------------------------------------------------
-- Extended schema for data profiling information according to KLMS ontology
-----------------------------------------------------------------------------

-- ************* ISSUES ********************
-- TODO: Tables NOT yet included in the relational schema:
-- Dependency, FunctionalDependency, InclusionDependency
-- Joinability
-- Correlation
-- UniqueCombination

-- No need to specify table for Distribution => in CKAN, table public.resource will hold general metadata about each JSON profile.
 
-- ***************************************


--******************************************
--           DISTRIBUTIONS
--******************************************

CREATE TABLE klms.categorical_distribution
( distr_id text NOT NULL,
  type text NOT NULL, 
  count double precision,
  percentage double precision,
  PRIMARY KEY (distr_id, type)
);


CREATE TABLE klms.numerical_distribution
( distr_id text NOT NULL,
  count double precision,
  average double precision,
  stddev double precision,
  min double precision,
  max double precision,
  median double precision,
  percentile10 double precision,
  percentile25 double precision,
  percentile75 double precision,
  percentile90 double precision,
  kurtosis double precision,
  skewness double precision,
  variance double precision,
  PRIMARY KEY (distr_id)
);

--****************************************************
--           DATASETS (actually CKAN resources)
--****************************************************

-- IMPORTANT! Currently, profiling assumes a collection of rasters; although CKAN resource can be a single file only, in the database we keep info about each raster image (distinguished by its "name" in the profile).
-- ASSUMPTION: Ingest profiling information regarding raster imagery into the database.
-- CAUTION! Temporal-related information NOT available in currently extracted profiles from raster datasets.

CREATE TABLE klms.raster
( resource_id text NOT NULL,
  name text,
  format text,
  height integer,
  width integer,
  crs text,
  spatial_coverage geometry, 
  spatial_resolution double precision,
  start_date timestamp,
  end_date timestamp,
  temporal_resolution text,
  no_data_value text,
  PRIMARY KEY (resource_id, name),
  CONSTRAINT fk_raster_id FOREIGN KEY(resource_id) REFERENCES public.resource(id) ON UPDATE CASCADE ON DELETE CASCADE
);



CREATE TABLE klms.tabular
( resource_id text NOT NULL,
  num_rows integer,
  num_columns integer,   -- CAUTION! called num_attributes in current profiles
  PRIMARY KEY (resource_id),
  CONSTRAINT fk_tabular_id FOREIGN KEY(resource_id) REFERENCES public.resource(id) ON UPDATE CASCADE ON DELETE CASCADE
);



CREATE TABLE klms.hierarchical
( resource_id text NOT NULL,
  num_records integer,
  num_attributes integer,
  depth_distribution text,
  PRIMARY KEY (resource_id),
  CONSTRAINT fk_hierarchical_id FOREIGN KEY(resource_id) REFERENCES public.resource(id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_depth_distribution FOREIGN KEY(depth_distribution) REFERENCES klms.numerical_distribution(distr_id)
);

-- Using a trigger to handle deletions from distribution(s):

CREATE OR REPLACE FUNCTION klms.syncHierarchicalDistribution() RETURNS trigger AS $funcHierDistr$
DECLARE
   depthdistr_id text;
BEGIN
   depthdistr_id := (OLD).depth_distribution;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = depthdistr_id;
   RETURN OLD;
END
$funcHierDistr$ LANGUAGE plpgsql;

CREATE TRIGGER klms_trigger_HierDistr
AFTER DELETE ON klms.hierarchical FOR EACH ROW EXECUTE FUNCTION klms.syncHierarchicalDistribution();



-- CAUTION! Currently extracted profiles of RDF graphs do NOT include attribute information (in variables).

CREATE TABLE klms.rdfgraph
( resource_id text NOT NULL,
  num_nodes integer,
  num_edges integer,
  num_namespaces integer,
  num_classes integer,
  num_object_properties integer,
  num_datatype_properties integer,
  density double precision,
  num_connected_components integer,
  degree_centrality_distribution text,
  degree_distribution text,
  in_degree_distribution text,
  out_degree_distribution text,
  class_distribution text,
  PRIMARY KEY (resource_id),
  CONSTRAINT fk_rdfgraph_id FOREIGN KEY(resource_id) REFERENCES public.resource(id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_degree_centrality_distribution FOREIGN KEY(degree_centrality_distribution) REFERENCES klms.numerical_distribution(distr_id),
  CONSTRAINT fk_degree_distribution FOREIGN KEY(degree_distribution) REFERENCES klms.numerical_distribution(distr_id),
  CONSTRAINT fk_in_degree_distribution FOREIGN KEY(in_degree_distribution) REFERENCES klms.numerical_distribution(distr_id),
  CONSTRAINT fk_out_degree_distribution FOREIGN KEY(out_degree_distribution) REFERENCES klms.numerical_distribution(distr_id)
);

-- Foreign key NOT possible to apply, due to primary key restrictions:
-- CONSTRAINT fk_class_distribution FOREIGN KEY(class_distribution) REFERENCES klms.categorical_distribution(distr_id) ON UPDATE CASCADE ON DELETE CASCADE
-- Instead, using a trigger to handle deletions for all distributions:
 
CREATE OR REPLACE FUNCTION klms.syncRdfDistribution() RETURNS trigger AS $funcRdfDistr$
DECLARE
   centrdistr_id text;
   degrdistr_id text;
   indegrdistr_id text;
   outdegrdistr_id text;
   classdistr_id text;
BEGIN
   centrdistr_id := (OLD).degree_centrality_distribution;
   degrdistr_id := (OLD).degree_distribution;
   indegrdistr_id := (OLD).in_degree_distribution;
   outdegrdistr_id := (OLD).out_degree_distribution;
   classdistr_id := (OLD).class_distribution;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = centrdistr_id;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = degrdistr_id;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = indegrdistr_id;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = outdegrdistr_id;
   DELETE FROM klms.categorical_distribution C
   WHERE C.distr_id = classdistr_id;
   RETURN OLD;
END
$funcRdfDistr$ LANGUAGE plpgsql;

CREATE TRIGGER klms_trigger_RdfDistr
AFTER DELETE ON klms.rdfgraph FOR EACH ROW EXECUTE FUNCTION klms.syncRdfDistribution();



-- IMPORTANT! Currently, profiling assumes a collection of texts; although CKAN resource can be a single file only, in the database we keep info about each text document (distinguished by its "name" in the profile).
-- ASSUMPTION: Ingest profiling information regarding each text document from the corpus into the database.

CREATE TABLE klms.text
( resource_id text NOT NULL,
  name text,
  language text,
  num_sentences integer,
  num_words integer,
  num_distinct_words integer,
  num_characters integer,
  ratio_uppercase double precision,
  ratio_digits double precision,
  ratio_special_characters double precision,
  sentence_length_distribution text,
  word_length_distribution text,
  special_characters_distribution text,
  language_distribution text,
  PRIMARY KEY (resource_id, name),
  CONSTRAINT fk_text_id FOREIGN KEY(resource_id) REFERENCES public.resource(id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_sentence_length_distribution FOREIGN KEY(sentence_length_distribution) REFERENCES klms.numerical_distribution(distr_id),
  CONSTRAINT fk_word_length_distribution FOREIGN KEY(word_length_distribution) REFERENCES klms.numerical_distribution(distr_id)
);


-- Foreign key NOT possible to apply, due to primary key restrictions:
-- CONSTRAINT fk_language_distribution FOREIGN KEY(language_distribution) REFERENCES klms.categorical_distribution(distr_id) ON UPDATE CASCADE ON DELETE CASCADE
-- CONSTRAINT fk_special_characters_distribution FOREIGN KEY(special_characters_distribution) REFERENCES klms.categorical_distribution(distr_id) ON UPDATE CASCADE ON DELETE CASCADE
-- Instead, using a trigger to handle deletions:

CREATE OR REPLACE FUNCTION klms.syncTextDistribution() RETURNS trigger AS $funcTextDistr$
DECLARE
   sentencedistr_id text;
   worddistr_id text;
   langdistr_id text;
   charsdistr_id text;
BEGIN
   sentencedistr_id := (OLD).sentence_length_distribution;
   worddistr_id := (OLD).word_length_distribution;
   langdistr_id := (OLD).language_distribution;
   charsdistr_id := (OLD).special_characters_distribution;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = sentencedistr_id;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = worddistr_id;
   DELETE FROM klms.categorical_distribution C
   WHERE C.distr_id = langdistr_id;
   DELETE FROM klms.categorical_distribution C
   WHERE C.distr_id = charsdistr_id;
   RETURN OLD;
END
$funcTextDistr$ LANGUAGE plpgsql;

CREATE TRIGGER klms_trigger_TextDistr
AFTER DELETE ON klms.text FOR EACH ROW EXECUTE FUNCTION klms.syncTextDistribution();



--******************************************
--           ATTRIBUTES
--******************************************

-- CAUTION! Includes parent_id for hierarchical datasets; value NOT currently available in profiles
-- TODO: thematic category (dcat:theme) NOT available in currently extracted profiles.
-- TODO: missing_ratio NOT available in currently extracted profiles; available properties are num_missing, count.

CREATE TABLE klms.attribute
( resource_id text NOT NULL,
  attr_id text NOT NULL,
  attr_name text,
  type text,
  count double precision, 
  num_missing double precision, 
  uniqueness double precision,
  nesting_level integer,
  parent_id text,
  PRIMARY KEY (attr_id),
  CONSTRAINT fk_attribute_resource_id FOREIGN KEY(resource_id) REFERENCES public.resource(id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_parent_id FOREIGN KEY(parent_id) REFERENCES klms.attribute(attr_id)
);



CREATE TABLE klms.categorical_attribute
( attr_id text NOT NULL,
  frequency_distribution text,
  PRIMARY KEY (attr_id),
  CONSTRAINT fk_categorical_attr_id FOREIGN KEY(attr_id) REFERENCES klms.attribute(attr_id) ON UPDATE CASCADE ON DELETE CASCADE
);

-- Foreign key NOT possible to apply, due to primary key restrictions:
-- CONSTRAINT fk_categorical_frequency_distribution FOREIGN KEY(frequency_distribution) REFERENCES klms.categorical_distribution(distr_id) ON UPDATE CASCADE ON DELETE CASCADE

-- Instead, using a trigger to handle deletions:
 

CREATE OR REPLACE FUNCTION klms.syncFrequencyDistribution() RETURNS trigger AS $funcFreqDistr$
DECLARE
   freqdistr_id text;
BEGIN
   freqdistr_id := (OLD).frequency_distribution;
   DELETE FROM klms.categorical_distribution C
   WHERE C.distr_id = freqdistr_id;
   RETURN OLD;
END
$funcFreqDistr$ LANGUAGE plpgsql;

CREATE TRIGGER klms_trigger_FreqDistr
AFTER DELETE ON klms.categorical_attribute FOR EACH ROW EXECUTE FUNCTION klms.syncFrequencyDistribution();



CREATE TABLE klms.textual_attribute
( attr_id text NOT NULL,
  ratio_uppercase double precision,
  ratio_digits double precision,
  ratio_special_characters double precision,
  num_chars_distribution text,
  num_words_distribution text,
  PRIMARY KEY (attr_id),
  CONSTRAINT fk_categorical_attr_id FOREIGN KEY(attr_id) REFERENCES klms.attribute(attr_id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_num_chars_distribution FOREIGN KEY(num_chars_distribution) REFERENCES klms.numerical_distribution(distr_id),
  CONSTRAINT fk_num_words_distribution FOREIGN KEY(num_words_distribution) REFERENCES klms.numerical_distribution(distr_id)
);


CREATE OR REPLACE FUNCTION klms.syncTextAttrDistribution() RETURNS trigger AS $funcTextAttrDistr$
DECLARE
   charsdistr_id text;
   wordsdistr_id text;
BEGIN
   charsdistr_id := (OLD).num_chars_distribution;
   wordsdistr_id = (OLD).num_words_distribution;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = charsdistr_id;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = wordsdistr_id;
   RETURN OLD;
END
$funcTextAttrDistr$ LANGUAGE plpgsql;

CREATE TRIGGER klms_trigger_TextAttrDistr
AFTER DELETE ON klms.textual_attribute FOR EACH ROW EXECUTE FUNCTION klms.syncTextAttrDistribution();



CREATE TABLE klms.numerical_attribute
( attr_id text NOT NULL,
  value_distribution text,
  PRIMARY KEY (attr_id),
  CONSTRAINT fk_numerical_attr_id FOREIGN KEY(attr_id) REFERENCES klms.attribute(attr_id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_numerical_value_distribution FOREIGN KEY(value_distribution) REFERENCES klms.numerical_distribution(distr_id)
);

-- Using a trigger to handle deletions for distributions:

CREATE OR REPLACE FUNCTION klms.syncNumAttrDistribution() RETURNS trigger AS $funcNumAttrDistr$
DECLARE
   valdistr_id text;
BEGIN
   valdistr_id := (OLD).value_distribution; 
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = valdistr_id;
   RETURN OLD;
END
$funcNumAttrDistr$ LANGUAGE plpgsql;


CREATE TRIGGER klms_trigger_NumAttrDistr
AFTER DELETE ON klms.numerical_attribute FOR EACH ROW EXECUTE FUNCTION klms.syncNumAttrDistribution();


-- Extra class specifically bands (as attributes) in rasters:

CREATE TABLE klms.band_attribute
( raster_name text NOT NULL,
  attr_id text NOT NULL,
  value_distribution text,
  no_data_distribution text,
  PRIMARY KEY (raster_name, attr_id),
  CONSTRAINT fk_band_attr_id FOREIGN KEY(attr_id) REFERENCES klms.attribute(attr_id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_band_value_distribution FOREIGN KEY(value_distribution) REFERENCES klms.numerical_distribution(distr_id)
);


-- Foreign key NOT possible to apply, due to primary key restrictions:
--   CONSTRAINT fk_band_raster_name FOREIGN KEY(raster_name) REFERENCES klms.raster(name) ON UPDATE CASCADE ON DELETE CASCADE,
-- CONSTRAINT fk_band_nodata_distribution FOREIGN KEY(no_data_distribution) REFERENCES klms.categorical_distribution(distr_id) ON UPDATE CASCADE ON DELETE CASCADE
-- Instead, using a trigger to handle deletions for all distributions:

CREATE OR REPLACE FUNCTION klms.syncBandAttrDistribution() RETURNS trigger AS $funcBandAttrDistr$
DECLARE
   valdistr_id text;
   nodatadistr_id text;
BEGIN
   valdistr_id := (OLD).value_distribution; 
   nodatadistr_id := (OLD).no_data_distribution; 
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = valdistr_id;
   DELETE FROM klms.categorical_distribution C
   WHERE C.distr_id = nodatadistr_id;
   RETURN OLD;
END
$funcBandAttrDistr$ LANGUAGE plpgsql;


CREATE TRIGGER klms_trigger_BandAttrDistr
AFTER DELETE ON klms.band_attribute FOR EACH ROW EXECUTE FUNCTION klms.syncBandAttrDistribution();




CREATE TABLE klms.series_attribute
( attr_id text NOT NULL,
  num_peaks double precision,
  abs_energy double precision,
  abs_sum_changes double precision,
  len_above_mean double precision,
  len_below_mean double precision,
  value_distribution text,
  PRIMARY KEY (attr_id),
  CONSTRAINT fk_series_attr_id FOREIGN KEY(attr_id) REFERENCES klms.attribute(attr_id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_series_value_distribution FOREIGN KEY(value_distribution) REFERENCES klms.numerical_distribution(distr_id)
);


CREATE OR REPLACE FUNCTION klms.syncSeriesValueDistribution() RETURNS trigger AS $funcSeriesValueDistr$
DECLARE
   valdistr_id text;
BEGIN
   valdistr_id := (OLD).value_distribution; 
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = (OLD).value_distribution;
   RETURN OLD;
END
$funcSeriesValueDistr$ LANGUAGE plpgsql;


CREATE TRIGGER klms_trigger_SeriesValueDistr
AFTER DELETE ON klms.series_attribute FOR EACH ROW EXECUTE FUNCTION klms.syncSeriesValueDistribution();


-- CAUTION! Added resolution_distribution REFERENCES klms.numerical_distribution; TODO: provide resolution statistics for temporal attributes in resulting profiles


CREATE TABLE klms.temporal_attribute
( attr_id text NOT NULL,
  start_time timestamp,
  end_time timestamp,
  resolution_distribution text,
  PRIMARY KEY (attr_id),
  CONSTRAINT fk_temporal_attr_id FOREIGN KEY(attr_id) REFERENCES klms.attribute(attr_id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_temporal_resolution_distribution FOREIGN KEY(resolution_distribution) REFERENCES klms.numerical_distribution(distr_id)
);

CREATE OR REPLACE FUNCTION klms.syncResolutionDistribution() RETURNS trigger AS $funcResolutionDistr$
DECLARE
   resdistr_id text;
BEGIN
   resdistr_id := (OLD).resolution_distribution; 
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = resdistr_id;
   RETURN OLD;
END
$funcResolutionDistr$ LANGUAGE plpgsql;


CREATE TRIGGER klms_trigger_TemporalResolutionDistr
AFTER DELETE ON klms.temporal_attribute FOR EACH ROW EXECUTE FUNCTION klms.syncResolutionDistribution();


CREATE TABLE klms.geometry_attribute
( attr_id text NOT NULL,
  mbr geometry(Geometry,4326), 
  centroid geometry(Point,4326), 
  crs text,
  length_distribution text, 
  area_distribution text, 
  geom_type_distribution text,
  PRIMARY KEY (attr_id),
  CONSTRAINT fk_geometry_attr_id FOREIGN KEY(attr_id) REFERENCES klms.attribute(attr_id) ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_length_distribution FOREIGN KEY(length_distribution) REFERENCES klms.numerical_distribution(distr_id),
  CONSTRAINT fk_area_distribution FOREIGN KEY(area_distribution) REFERENCES klms.numerical_distribution(distr_id)
);

-- Foreign key NOT possible to apply, due to primary key restrictions:
-- CONSTRAINT fk_geom_type_distribution FOREIGN KEY(geom_type_distribution) REFERENCES klms.categorical_distribution(distr_id) ON UPDATE CASCADE ON DELETE CASCADE

-- Instead, using triggers to handle deletions:
 

CREATE OR REPLACE FUNCTION klms.syncGeomAttrDistribution() RETURNS trigger AS $funcGeomAttrDistr$
DECLARE
   geomdistr_id text;
   lengthdistr_id text;
   areadistr_id text;
BEGIN
   geomdistr_id := (OLD).geom_type_distribution;
   lengthdistr_id := (OLD).length_distribution;
   areadistr_id := (OLD).area_distribution;
   DELETE FROM klms.categorical_distribution C
   WHERE C.distr_id = geomdistr_id;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = lengthdistr_id;
   DELETE FROM klms.numerical_distribution N
   WHERE N.distr_id = areadistr_id;
   RETURN OLD;
END
$funcGeomAttrDistr$ LANGUAGE plpgsql;


CREATE TRIGGER klms_trigger_GeomAttrDistr
AFTER DELETE ON klms.geometry_attribute FOR EACH ROW EXECUTE FUNCTION klms.syncGeomAttrDistribution();