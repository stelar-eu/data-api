import logging
from apiflask import APIBlueprint
from flask import (
    current_app,
    jsonify,
    request,
)
from routes.generic import render_api_output
from backend.ckan import ckan_request
import schema
import utils
import json
from exceptions import NotFoundError, InvalidError
from auth import token_active
from backend.pgsql import execSql
from auth import security_doc
import pandas as pd
from cutils import DATASET


# The tasks operations blueprint for all operations related to the lifecycle of `tasks
ranking_bp = APIBlueprint("ranking_bp", __name__, enable_openapi=False)

logger = logging.getLogger(__name__)


@ranking_bp.route("/catalog/rank", methods=["POST"])
@ranking_bp.input(
    schema.Ranking,
    location="json",
    example={
        "rank_preferences": {
            "tags": ["Geospatial", "POI"],
            "theme": ["Land Use", "Land Cover", "Imagery"],
            "language": ["en", "el", "fr"],
            "spatial": {
                "type": "Polygon",
                "coordinates": [
                    [
                        [12.362, 45.39],
                        [12.485, 45.39],
                        [12.485, 45.576],
                        [12.362, 45.576],
                        [12.362, 45.39],
                    ]
                ],
            },
        },
        "settings": {"k": 10, "algorithm": "threshold", "weights": [0.3, 0.5, 0.4]},
    },
)
@ranking_bp.output(schema.APIResponse, status_code=200)
@ranking_bp.doc(tags=["Ranking Operations"], security=security_doc)
@render_api_output(logger)
@token_active
def api_catalog_rank(json_data):
    """Submit a rank request regarding specific metadata attributes (facets) to the Data Catalog.

    Args:
        json_data: A JSON with facet preferences for searching in the Data Catalog. Facet name should match a property specified in the STELAR Ontology.

    Returns:
        A JSON with datasets ranked by the specified facet(s). The matching score per facet criterion is also listed per returned dataset.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:9055/api/v1/catalog/rank -d '{"q":{"theme":"POI"}}'

    config = current_app.config["settings"]

    sql = ""
    sql_id_filter = ""
    ids = []
    dict_df_facet_scores = (
        {}
    )  # dictionary with the returned input ranked lists per facet (key -> dataframe)
    k = config["RANK_MAX_TOPK"]  # default top-k value (if not user-specified)
    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        actual_profile_attributes = set(
            specs.get("filter_preferences", {}).keys()
        ).union(set(specs.get("rank_preferences", {}).keys()))
        #        print("INITIAL PROFILE ATTRIBUTES", actual_profile_attributes)

        # STAGE #1: text-based keyword search targets SOLR (search engine for CKAN)
        if "keywords" in specs:  # CASE #1(a): new keyword search
            # q = "?q=" + ",".join("'{0}'".format(kw) for kw in specs["keywords"])
            #            print(q)
            # Submit a preliminary search request to CKAN to find packages qualifying to the specified keywords
            # Also include private datasets of the user's organization in the results
            # resp_basic = requests.get(
            #     config["CKAN_API"]
            #     + "package_search"
            #     + q
            #     + "&include_private=True&fl=*,score&rows="
            #     + str(config["RANK_MAX_TOPK"])
            #     + "&start=0",
            #     headers=package_headers,
            # )
            #     if resp_basic.status_code == 200:
            #         json_resp_basic = resp_basic.json()
            #         # FIXME: Handle large number of returned id's -> not efficient when filtering with SQL
            #         if json_resp_basic["success"]:  # Results from keyword-based search only
            #             results = json_resp_basic["result"]["results"]
            #             ids = [res["id"] for res in results if "id" in res]
            # #                    print('keyword results:',len(ids))

            packages = DATASET.search(
                {
                    "q": ",".join("{0}".format(kw) for kw in specs["keywords"]),
                    "limit": int(config["RANK_MAX_TOPK"]),
                    "offset": 0,
                    "fl": ["*", "score"],
                }
            )

            if packages.get("results", False):
                ids = [pkg["id"] for pkg in packages["results"] if "id" in pkg]
            logger.debug("Keyword search results: %s", len(ids))

        elif (
            "ids" in specs
        ):  # CASE #1(b): Identifiers of datasets already qualifying keyword search criteria
            if len(specs["ids"]) > 0:
                ids = specs["ids"]
        if len(ids) > 0:  # Specify the previously filtered items to be sent for ranking
            sql_id_filter, k = utils.format_sql_filter(ids)
        else:  # No results from filtering, no sense to continue with further filtering
            return {
                "count": 0,
                "facets": {},
                "results": [],
                "sort": "score desc, metadata_modified desc",
            }

        # STAGE #2: Apply any filtering criteria (NOT participating in the ranking)
        if "filter_preferences" in specs:
            filter_sql_commands = utils.format_facet_preferences(
                specs["filter_preferences"], sql_id_filter, config["RANK_MAX_TOPK"]
            )
            # Submit each SELECT query to the PostgreSQL database with the respective parameters
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            for key in filter_sql_commands.keys():
                sql = filter_sql_commands[key]
                results = utils.execSql(sql)
                #                print(len(results), sql)
                filter_ids = [res["id"] for res in results if "id" in res]
                if sql_id_filter == "":  # No keywords specified in search bar
                    ids = filter_ids
                else:  # Keep only matching id's
                    ids = [id for id in ids if id in filter_ids]
        #                print(key, len(ids))
        if len(ids) > 0:  # Specify the previously filtered items to be sent for ranking
            sql_id_filter, k = utils.format_sql_filter(ids)
        else:  # No results from filtering, no sense to apply ranking
            return {
                "count": 0,
                "facets": {},
                "results": [],
                "sort": "score desc, metadata_modified desc",
            }

        # STAGE #3: Prepare SQL queries for each of the ranking preferences
        if "rank_preferences" in specs:
            rank_sql_commands = utils.format_facet_preferences(
                specs["rank_preferences"], sql_id_filter, config["RANK_MAX_TOPK"]
            )
            # FIXME: REMOVE IF HANDLED BY THE FRONT-END
            # Examine settings for ranking
            #            if 'settings' in specs:
            #                if not 'algorithm' in specs['settings']: # Apply default algorithm for rank aggregation
            #                    specs['settings']['algorithm'] = config['RANK_AGG_ALGORITHM']
            #                if 'k' in specs['settings']:
            #                    k = specs['settings']['k']
            #                else:
            #                    specs['settings']['k'] = k    # Rank aggregation library requires the total number of items
            #                    print(specs['settings']['k'])
            #            else:  # Specify default values for rank aggregation
            #                specs['settings'] = {}
            #                specs['settings']['algorithm'] = config['RANK_AGG_ALGORITHM']
            #                specs['settings']['k'] = k

            # Submit each SELECT query to the PostgreSQL database with the respective parameters
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            input_lists = []
            for key in rank_sql_commands.keys():
                sql = rank_sql_commands[key]
                #                print(key, '->', sql)
                results = utils.execSql(sql)
                #                print("FIELDS", key, len(results), len(ids))
                # Fill any missing scores in the partial list for this facet
                for id in ids:
                    if id not in [d["id"] for d in results if "id" in d]:
                        results.append({"id": id, "score": 0.0})
                dict_df_facet_scores[key] = utils.read_list_json(results)
            #                # In case a 'value' column (concerning PROFILING) is returned in results, remember to include its values in the final results
            #                if 'value' in dict_df_facet_scores[key].columns:
            #                    profile_attributes.append(key)
            #                    print(key)

            # Fetch values for all profiling metadata elements by submitting a SELECT query to the PostgreSQL database for the collected ids
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            actual_profile_attributes = actual_profile_attributes.intersection(
                utils.profile_attributes
            )

            for key in list(
                actual_profile_attributes
            ):  # list(set(utils.profile_attributes) - set(rank_sql_commands.keys())):
                sql = utils.identifiers_sql_filter_template.replace(
                    "_VIEW", utils.sql_views[key]
                ).replace("_IDS", sql_id_filter)
                #                print(key, '->', sql)
                results = utils.execSql(sql)
                print("PROFILING", key, len(results), len(ids))
                # Fill any missing scores in the partial list for this facet
                for id in ids:
                    if id not in [d["id"] for d in results if "id" in d]:
                        results.append({"id": id, "score": 0.0})
                dict_df_facet_scores[key] = utils.read_list_json(results)

                input_lists.append(dict_df_facet_scores[key])

            # FIXME: REMOVE IF HANDLED BY THE FRONT-END
            agg_scores = (
                pd.DataFrame()
            )  # No aggregated scores, report the original SOLR scores

            # Compute the final ranked list of all items applying the specified rank aggregation method (e.g., threshold)
        #            agg_scores = ranking.combined_ranking(input_lists, specs['settings'])
        #            ids = agg_scores.index.values  # In case no keywords and no filter criteria have been spcified; only rank preferences
        #            print(agg_scores.index.values)
        elif (
            "settings" in specs
        ):  # Settings for rank aggregation assume at least once facet specification
            raise InvalidError(
                "Incorrect or no facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary."
            )

        else:  # No ranking to be applied; only search filters
            specs["rank_preferences"] = {}  # Facets for ranking not specified
            agg_scores = (
                pd.DataFrame()
            )  # No aggregated scores, report the original SOLR scores
    else:
        raise InvalidError(
            "Incorrect or no facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary."
        )

    # Retrieve from CKAN all metadata for the datasets in the final (aggregated ranked) list
    # Also include private datasets of the user's organization in the results
    # q = "?q=" + " OR ".join(["id:" + id for id in ids])
    # response = requests.get(
    #     config["CKAN_API"]
    #     + "package_search"
    #     + q
    #     + "&rows="
    #     + str(config["RANK_MAX_TOPK"])
    #     + "&start=0&include_private=True",
    #     headers=package_headers,
    # )

    response = DATASET.search(
        {
            "q": " OR ".join(["id:" + id for id in ids]),
            "limit": int(config["RANK_MAX_TOPK"]),
            "offset": 0,
            "fl": ["*", "score"],
        }
    )

    logger.debug(" Facet scores: %s", dict_df_facet_scores)
    # Return the final list of results (the top-k ranked ones in case that ranking preferences are specified)
    return utils.assign_scores(
        response,
        agg_scores,
        dict_df_facet_scores,
        specs["rank_preferences"],
        list(actual_profile_attributes),
    )


@ranking_bp.route("facet/values", methods=["POST"])
@ranking_bp.input(schema.Filter, location="json", example={"q": "format"})
@ranking_bp.output(schema.IdListResponse, status_code=200)
@token_active
def api_facet_values(json_data):
    """Submit a request to fetch all values available for a specific facet in the Data Catalog.

    Args:
        json_data: A JSON specifying the facet name (corresponding to an SQL view or table) to query in the PostgreSQL database of the Data Catalog.

    Returns:
        A JSON with all values available for the specified facet.
    """

    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        # Identify the SQL view that corresponds to the specified facet
        if "q" in specs and utils.sql_views.get(specs["q"]):
            view_name = str(utils.sql_views.get(specs["q"]))
            sql = "SELECT * FROM " + view_name
        #            print(sql)
        else:
            raise NotFoundError(
                "No valid facet available to fetch its values from the Data Catalog. Please specify a valid name for SQL view."
            )
    else:
        raise InvalidError(
            "No valid JSON data provided. Please specify a valid JSON with the facet name."
        )

    # Execute the SQL view to fetch the values
    results = execSql(sql)

    # Exclude identifiers from the returned results
    for res in results:
        if "id" in res:
            del res["id"]
        elif "package_id" in res:
            del res["package_id"]

    return jsonify(results)
