# Overview
This is the Data API for the Knowledge Lake Management System developed in project [STELAR](https://stelar-project.eu/). This REST API enables interaction with the Data Catalog, allowing users to publish datasets, search for datasets with various criteria (like keywords, spatial, or temporal) and also submit SPARQL queries against a Knowledge Graph.

# Prerequisites 

* This REST API assumes that a Data Catalog has been deployed using [CKAN](https://ckan.org/), including a [PostgreSQL](https://www.postgresql.org/)/[PostGIS](http://postgis.net/) database where all metadata about published datasets (i.e., CKAN packages and resources) is maintained.

* A [custom schema](https://github.com/stelar-eu/klms-core-components-setup/tree/main/data-catalog/schema-extension) must have been created in the PostgreSQL database where the Data Catalog holds all metadata. Apart from metadata about published datasets (i.e., CKAN packages and resources), this database also hold metadata about workflow and task executions, as well as data profiling information.

* A Knowledge Graph must have been deployed via [Ontop](https://ontop-vkg.org/), employing mappings from the database to a virtual RDF graph that can be queried in SPARQL.


# Creating and launching a Docker image 

We provide an indicative `Dockerfile` that may be used to create a Docker image (`data_api`) from the source code:

```sh
$ docker build -t data_api .
```

Before deploying the API as a service, you must specify required parameters in a `config.yaml` file. Copy `config-example.yaml` to `config.yaml` and fill in values for all parameters specified in `<...>` (e.g., `<API-PORT>`, `<CKAN-HOST>`, credentials for connection to the underlying PostgreSQL database, etc.).

The docker image can then be used to launch a web service application at a specific port (e.g., 9055) as follows:

```sh
$ docker run --name data_api -p 9055:9055 data_api ./config.yaml
```

Once the service is launched, requests can be sent to this REST API in order to publish and search datasets in the data lake.


# Documentation
Once the REST API is launched, full documentation about it will be available as an interactive HTML at: `http://<DATA-API-HOST>/docs`

# Specifications
Data API supports [OpenAPI 3.0](https://spec.openapis.org/oas/v3.0.3) specification. Once the REST API is launched, full specifications will be readily available as a JSON at: `http://<DATA-API-HOST>/specs`. A copy of these specifications is available [here](specs/OpenAPI_specs.json).


# License

The contents of this project are licensed under the [Apache License 2.0](https://github.com/stelar-eu/data-profiler/blob/main/LICENSE).