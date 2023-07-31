# Overview
This is the Data API for the Knowledge Lake Management System developed in project [STELAR](https://stelar-project.eu/). This REST API enables interaction with the Data Catalog, allowing users to publish datasets, search for datasets with various criteria (like keywords, spatial, or temporal) and also submit SPARQL queries against a Knowledge Graph.

# Prerequisites 

This REST API assumes that a Data Catalog has been deployed using [CKAN](https://ckan.org/), including a [PostgreSQL](https://www.postgresql.org/)/[PostGIS](http://postgis.net/) database where all metadata about datasets (i.e., CKAN packages and resources) is maintained.

A Knowledge Graph must have been deployed via [Ontop](https://ontop-vkg.org/), employing mappings from the database to a virtual RDF graph that can be queried in SPARQL.

Finally, an instance of [MLFlow](https://mlflow.org/) must be up-and-running, and metadata regarding all executions is maintained in the same database (the one also used by CKAN).


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
Full documentation about the Data API can be found at: http://data-api.magellan2.imsi.athenarc.gr/docs

# Specifications
Data API supports [OpenAPI 3.0](https://spec.openapis.org/oas/v3.0.3) specification. Full specifications are available at: http://data-api.magellan2.imsi.athenarc.gr/specs


# License

The contents of this project are licensed under the [Apache License 2.0](https://github.com/stelar-eu/data-profiler/blob/main/LICENSE).