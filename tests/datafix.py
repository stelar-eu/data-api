"""
Code to help with fixtures that generate STELAR entities and data
to use in tests.

Many of the tests require such data to be present and to be cleaned
up afterwards.
"""


from abc import ABC, abstractmethod
from collections import defaultdict

from backend.ckan import disband_relationship, establish_relationship
from cutils import DATASET
from entity import Entity
from wflow import WORKFLOW


class Datum(ABC):
    """An abstract class to represent a temporary entity"""

    @abstractmethod
    def create(self):
        """Create the entity in the system"""
        return NotImplemented

    @abstractmethod
    def destroy(self):
        """Delete the entity from the system"""
        return NotImplemented


class EntityInstance(Datum):
    """An abstract class to represent a temporary entity"""

    def __init__(self, entity: Entity, init_data: dict):
        self.entity = entity
        self.init_data = init_data
        self.instance = None
        self.instantiated = False

    @property
    def type(self):
        return self.entity.name

    def create(self):
        self.instance = self.entity.create(self.init_data)
        self.instantiated = True
        return self.instance

    def destroy(self):
        if self.instantiated:
            self.entity.delete(self.instance["id"], purge=True)
            self.instantiated = False
            self.instance = None


class RelDatum(Datum):
    def __init__(
        self,
        subid: str,
        objid: str,
        rel: str,
        comment: str = None,
    ):
        self.subid = subid
        self.objid = objid
        self.rel = rel
        self.comment = comment
        self.instantiated = False

    @property
    def type(self):
        return "relationship"

    def create(self):
        establish_relationship(
            "create",
            subid=self.subid,
            objid=self.objid,
            rel=self.rel,
            comment=self.comment,
        )
        self.instantiated = True

    def destroy(self):
        if self.instantiated:
            disband_relationship(
                subid=self.subid,
                objid=self.objid,
                rel=self.rel,
            )
            self.instantiated = False


class DataFix:
    def __init__(self):
        self.requires: list[DataFix] = []
        self.data: list[Datum] = []
        self.data_by_type: dict[str, list[Datum]] = defaultdict(list)
        self.instantiated = False

    def add(self, datum: Datum):
        """Add a datum to the data fix"""
        datum.idno = len(self.data)
        self.data.append(datum)
        self.data_by_type[datum.type].append(datum)

    def create(self):
        """Create all the data in the data fix"""
        for datum in self.data:
            datum.create()
        self.instantiated = True

    def destroy(self):
        """Destroy all the data in the data fix"""
        for datum in reversed(self.data):
            datum.destroy()
        self.instantiated = False

    # Code for creating entities and relationships
    def dataset(self, **init_data):
        datum = EntityInstance(DATASET, init_data)
        self.add(datum)
        return datum

    def workflow(self, **init_data):
        datum = EntityInstance(WORKFLOW, init_data)
        self.add(datum)
        return datum

    def relationship(self, subid: str, objid: str, rel: str, comment: str = None):
        datum = RelDatum(
            subid=subid,
            objid=objid,
            rel=rel,
            comment=comment,
        )
        self.add(datum)
        return datum
