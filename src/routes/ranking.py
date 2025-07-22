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

    config = current_app.config["settings"]

    sql = ""
    sql_id_filter = ""
    ids = []
    dict_df_facet_scores = {}
    k = config["RANK_MAX_TOPK"]
    
    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        actual_profile_attributes = set(
            specs.get("filter_preferences", {}).keys()
        ).union(set(specs.get("rank_preferences", {}).keys()))

        # STAGE #1: Keyword search
        if "keywords" in specs:
            packages = DATASET.search(
                {
                    "q": ",".join("{0}".format(kw) for kw in specs["keywords"]),
                    "limit": int(config["RANK_MAX_TOPK"]),
                    "offset": 0,
                    #"fl": ["*", "score"],
                }
            )

            if packages.get("results", False):
                ids = [pkg["id"] for pkg in packages["results"] if "id" in pkg]
            logger.debug("Keyword search results: %s", len(ids))

        elif "ids" in specs:
            if len(specs["ids"]) > 0:
                ids = specs["ids"]
                
        if len(ids) > 0:
            sql_id_filter, k = utils.format_sql_filter(ids)
        else:
            return {
                "count": 0,
                "facets": {},
                "results": [],
                "sort": "score desc, metadata_modified desc",
            }

        # STAGE #2: Apply filtering criteria
        if "filter_preferences" in specs:
            try:
                filter_sql_commands = utils.format_facet_preferences(
                    specs["filter_preferences"], sql_id_filter, config["RANK_MAX_TOPK"]
                )
                
                for key in filter_sql_commands.keys():
                    sql = filter_sql_commands[key]
                    try:
                        results = utils.execSql(sql)
                        filter_ids = [res["id"] for res in results if "id" in res]
                        if sql_id_filter == "":
                            ids = filter_ids
                        else:
                            ids = [id for id in ids if id in filter_ids]
                    except Exception as e:
                        logger.error("Filter SQL execution failed for key '%s': %s", key, str(e))
                        logger.error("SQL: %s", sql)
                        # Continue with original ids if filter fails
                        continue
                        
            except Exception as e:
                logger.error("Filter preferences processing failed: %s", str(e))
                # Continue without filtering
                pass
                
        if len(ids) > 0:
            sql_id_filter, k = utils.format_sql_filter(ids)
        else:
            return {
                "count": 0,
                "facets": {},
                "results": [],
                "sort": "score desc, metadata_modified desc",
            }

        # STAGE #3: Ranking preferences
        if "rank_preferences" in specs:
            try:
                rank_sql_commands = utils.format_facet_preferences(
                    specs["rank_preferences"], sql_id_filter, config["RANK_MAX_TOPK"]
                )

                for key in rank_sql_commands.keys():
                    sql = rank_sql_commands[key]
                    try:
                        results = utils.execSql(sql)
                        # Fill missing scores
                        for id in ids:
                            if id not in [d["id"] for d in results if "id" in d]:
                                results.append({"id": id, "score": 0.0})
                        dict_df_facet_scores[key] = utils.read_list_json(results)
                    except Exception as e:
                        logger.error("Ranking SQL execution failed for key '%s': %s", key, str(e))
                        logger.error("SQL: %s", sql)
                        # Create empty dataframe for this facet
                        dict_df_facet_scores[key] = pd.DataFrame(columns=['score']).set_index(pd.Index([], name='id'))
                        continue

                # Handle profile attributes
                actual_profile_attributes = actual_profile_attributes.intersection(
                    utils.profile_attributes
                )

                for key in list(actual_profile_attributes):
                    if key not in dict_df_facet_scores:  # Only if not already processed
                        try:
                            sql = utils.identifiers_sql_filter_template.replace(
                                "_VIEW", utils.sql_views[key]
                            ).replace("_IDS", sql_id_filter)
                            results = utils.execSql(sql)
                            logger.debug("PROFILING %s: %d results, %d ids", key, len(results), len(ids))
                            
                            # Fill missing scores
                            for id in ids:
                                if id not in [d["id"] for d in results if "id" in d]:
                                    results.append({"id": id, "score": 0.0})
                            dict_df_facet_scores[key] = utils.read_list_json(results)
                        except Exception as e:
                            logger.error("Profile attribute SQL execution failed for key '%s': %s", key, str(e))
                            # Create empty dataframe for this facet
                            dict_df_facet_scores[key] = pd.DataFrame(columns=['score']).set_index(pd.Index([], name='id'))
                            continue

            except Exception as e:
                logger.error("Ranking preferences processing failed: %s", str(e))
                # Continue without ranking
                pass

            agg_scores = pd.DataFrame()  # No aggregated scores for now

        elif "settings" in specs:
            raise InvalidError(
                "Incorrect or no facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary."
            )
        else:
            specs["rank_preferences"] = {}
            agg_scores = pd.DataFrame()
    else:
        raise InvalidError(
            "Incorrect or no facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary."
        )

    # Retrieve final results from CKAN
    try:
        response = DATASET.search(
            {
                "q": " OR ".join(["id:" + id for id in ids]),
                "limit": int(config["RANK_MAX_TOPK"]),
                "offset": 0,
                #"fl": [],
            }
        )
    except Exception as e:
        logger.error("Final CKAN search failed: %s", str(e))
        return {
            "count": 0,
            "facets": {},
            "results": [],
            "sort": "score desc, metadata_modified desc",
            "error": "Failed to retrieve final results from CKAN"
        }

    logger.debug("Facet scores keys: %s", list(dict_df_facet_scores.keys()))
    
    # Return results with scores assigned
    return utils.assign_scores(
        response,
        agg_scores,
        dict_df_facet_scores,
        specs.get("rank_preferences", {}),
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
