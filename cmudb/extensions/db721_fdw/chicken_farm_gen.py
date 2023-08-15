#!/usr/bin/python
"""
This file generates data for the ChickenFarm benchmark.
The goal of this data generator is to vary the level of benefit
that an execution engine would observe from implementing
optimizations such as predicate pushdown.

Generates:
- data-chickens.db721
- data-farms.db721
- data-chickens.csv
- data-farms.csv
"""
import csv
import json
import math
import random

from dataclasses import dataclass
from struct import pack


@dataclass
class Chicken:
    identifier: int
    farm_name: str
    weight_model: str
    sex: str
    age_weeks: float
    weight_grams: float
    notes: str


class ChickenModels:
    """
    Models and parameter values based on
    M. Topal & Ş. C. Bolukbasi (2008),
    Comparison of Nonlinear Growth Curve Models in Broiler Chickens,
    Journal of Applied Animal Research
    https://www.tandfonline.com/doi/pdf/10.1080/09712119.2008.9706960

    TODO(WAN): Any models for general chicken types?
    """
    weight_models = ["GOMPERTZ", "WEIBULL", "MMF"]
    sexes = ["FEMALE", "MALE"]
    min_age_weeks = 0
    max_age_weeks = 52 * 12

    parameters = {
        "GOMPERTZ": {
            "FEMALE": {
                "A": 6282.347,
                "B": 5.313,
                "k": 0.268,
            },
            "MALE": {
                "A": 5453.802,
                "B": 4.916,
                "k": 0.265,
            },
        },
        "MMF": {
            "FEMALE": {
                "A": 41.542,
                "B": 275.155,
                "k": 15222.91,
                "D": 2.123,
            },
            "MALE": {
                "A": 38.714,
                "B": 424.566,
                "k": 31247.15,
                "D": 1.871,
            },
        },
        "WEIBULL": {
            "FEMALE": {
                "A": 8635.340,
                "B": 8594.225,
                "k": 0.006,
                "D": 2.110,
            },
            "MALE": {
                "A": 17435.182,
                "B": 17396.753,
                "k": 0.004,
                "D": 1.865,
            },
        },
    }

    @staticmethod
    def _weight_gompertz(sex, t):
        parameters = ChickenModels.parameters["GOMPERTZ"][sex]
        A, B, k = parameters["A"], parameters["B"], parameters["k"]
        return A * math.exp(-B * math.exp(-k * t))

    @staticmethod
    def _weight_mmf(sex, t):
        parameters = ChickenModels.parameters["MMF"][sex]
        A, B, k, D = parameters["A"], parameters["B"], parameters["k"], parameters["D"]
        return (A * B + k * math.pow(t, D)) / (B + math.pow(t, D))

    @staticmethod
    def _weight_weibull(sex, t):
        parameters = ChickenModels.parameters["WEIBULL"][sex]
        A, B, k, D = parameters["A"], parameters["B"], parameters["k"], parameters["D"]
        return A - B * math.exp(-k * math.pow(t, D))

    @staticmethod
    def weight_grams(sex, age_weeks, rand):
        weight = None
        if 0 <= age_weeks <= 6:
            weight_model = rand.choice(ChickenModels.weight_models)
            if weight_model == "GOMPERTZ":
                model = ChickenModels._weight_gompertz
            elif weight_model == "MMF":
                model = ChickenModels._weight_mmf
            else:
                assert weight_model == "WEIBULL"
                model = ChickenModels._weight_weibull
            assert model is not None
            weight = model(sex, age_weeks)
        else:
            # TODO(WAN): The above models are absurd for older chickens. Making up models...
            weight_model = "RNG"
            min_weight = 1800
            max_weight = 2100 + 200 * (age_weeks // 52)
            max_weight = min(max_weight, 4500)
            weight = rand.uniform(min_weight, max_weight)
        # Add some noise so that the weight isn't too predictable.
        noise_grams = rand.uniform(0, 445)
        final_weight = round(weight + noise_grams, 2)
        return weight_model, final_weight


class Mutation:
    @staticmethod
    def woody(chicken: Chicken, rand: random.Random):
        chicken.notes = "WOODY"
        chicken.weight_grams += rand.uniform(300, 600)
        return chicken


class ChickenFarm:
    def __init__(self, farm_name, sexes=None, min_age_weeks=None, max_age_weeks=None, mutation=None):
        self.farm_name: str = farm_name
        self.mutation = mutation
        self.sexes = sexes if sexes is not None else ChickenModels.sexes
        self.min_age_weeks = min_age_weeks if min_age_weeks is not None else ChickenModels.min_age_weeks
        self.max_age_weeks = max_age_weeks if max_age_weeks is not None else ChickenModels.max_age_weeks

    def generate_chicken(self, chicken_id, seed=None):
        rand = random.Random(seed)
        sex = rand.choice(self.sexes)
        age_weeks = round(rand.uniform(self.min_age_weeks, self.max_age_weeks), 2)
        weight_model, weight_grams = ChickenModels.weight_grams(sex, age_weeks, rand)

        chicken = Chicken(
            identifier=chicken_id,
            farm_name=self.farm_name,
            weight_model=weight_model,
            sex=sex,
            age_weeks=age_weeks,
            weight_grams=weight_grams,
            notes="",
        )
        return chicken if self.mutation is None else self.mutation(chicken, rand)


class Db721BlockStatistics:
    def __init__(self, col_type: str):
        self.col_type: str = col_type
        self.stats: dict = {}
        self.reset()

    def reset(self):
        self.stats = {
            "num": 0,
            "min": None,
            "max": None,
        }
        if self.col_type == "str":
            self.stats["min_len"] = None
            self.stats["max_len"] = None

    def process(self, col_val):
        def _update_key(op, stat_name, val):
            if self.stats[stat_name] is None:
                self.stats[stat_name] = val
            else:
                self.stats[stat_name] = op(val, self.stats[stat_name])

        self.stats["num"] += 1
        _update_key(min, "min", col_val)
        _update_key(max, "max", col_val)
        if self.col_type == "str":
            _update_key(min, "min_len", len(col_val))
            _update_key(max, "max_len", len(col_val))


class Db721Serializer:
    def __init__(self, table_name: str, outfile, max_values_per_block: int = 50000):
        self.json_schema = {"Table": table_name, "Columns": {}, "Max Values Per Block": max_values_per_block}
        self.outfile = outfile
        self.max_values_per_block = max_values_per_block
        self._num_values = 0
        self._current_block_offset = 0

    def _new_block(self):
        self._num_values = 0
        self._current_block_offset += 1

    def _serialize(self, col_type: str, col_val):
        bytes_val = None
        if col_type == "str":
            assert len(col_val) < 32, "Only support fixed-length null-terminated 32-byte strings."
            bytes_val = col_val.ljust(32, "\0").encode("ASCII")
        elif col_type == "int":
            bytes_val = pack("i", col_val)
        elif col_type == "float":
            bytes_val = pack("f", col_val)
        else:
            raise RuntimeError(f"Bad type: {col_type}, for {col_val}")

        if self._num_values >= self.max_values_per_block:
            return False
        self.outfile.write(bytes_val)
        self._num_values += 1
        return True

    def write_col(self, col_name: str, col_type: str, col_contents):
        assert col_name not in self.json_schema, "Duplicate column?"
        self._num_values = 0
        self._current_block_offset = 0

        self.json_schema["Columns"][col_name] = {
            "type": col_type,
            "block_stats": {},
            "num_blocks": 0,
            "start_offset": self.outfile.tell(),
        }

        col_stats = Db721BlockStatistics(col_type)
        for i, col_val in enumerate(col_contents):
            while True:
                could_serialize = self._serialize(col_type, col_val)
                if could_serialize:
                    col_stats.process(col_val)
                    break
                else:
                    # Ran out of space, start a new block.
                    self.json_schema["Columns"][col_name]["block_stats"][
                        self._current_block_offset] = col_stats.stats.copy()
                    col_stats.reset()
                    self._new_block()

        num_blocks = self._current_block_offset + 1
        self.json_schema["Columns"][col_name]["block_stats"][self._current_block_offset] = col_stats.stats.copy()
        self.json_schema["Columns"][col_name]["num_blocks"] = num_blocks
        return num_blocks

    def finalize(self):
        json_schema = json.dumps(self.json_schema)
        self.outfile.write(json_schema.encode("ASCII"))
        self.outfile.write(pack("i", len(json_schema)))


def main():
    scale_factor = 1
    next_chicken_id = 1
    seed = 15721
    rand = random.Random(seed)
    chickens = []
    db721_file_chickens = "data-chickens.db721"
    db721_file_farms = "data-farms.db721"
    csv_file_chickens = "data-chickens.csv"
    csv_file_farms = "data-farms.csv"

    def generate_chickens(num_chickens: int, farms: list[ChickenFarm]):
        nonlocal next_chicken_id
        for i in range(num_chickens):
            farm = rand.choice(farms)
            chicken = farm.generate_chicken(next_chicken_id, seed + next_chicken_id)
            chickens.append(chicken)
            next_chicken_id += 1

    # Define a few different types of farms.
    incubator_1 = ChickenFarm("Incubator", max_age_weeks=2)
    layer_1 = ChickenFarm("Eggscellent", sexes=["FEMALE"], min_age_weeks=4 * 6, max_age_weeks=52 * 3)
    layer_2 = ChickenFarm("Eggstraordinaire", sexes=["FEMALE"], min_age_weeks=52 * 1, max_age_weeks=52 * 3)
    broiler_1 = ChickenFarm("Breakfast Lunch Dinner", min_age_weeks=0, max_age_weeks=6)
    broiler_2 = ChickenFarm("Dish of the Day", sexes=["MALE"], min_age_weeks=0, max_age_weeks=8)
    broiler_3 = ChickenFarm("Cheep Birds", min_age_weeks=0, max_age_weeks=6, mutation=Mutation.woody)
    all_farms = [incubator_1, layer_1, layer_2, broiler_1, broiler_2, broiler_3]

    # The goal in generation is to get "runs" of data that would benefit from different optimizations.
    generate_chickens(50000 * scale_factor, [broiler_3])
    generate_chickens(30000 * scale_factor, [layer_1, layer_2])
    generate_chickens(30000 * scale_factor, [broiler_1, broiler_2, broiler_3, layer_1])
    generate_chickens(10000 * scale_factor, [incubator_1])

    with open(db721_file_farms, "wb") as f:
        serializer = Db721Serializer("Farm", f)
        serializer.write_col("farm_name", "str", [farm.farm_name for farm in all_farms])
        # TODO(WAN): list and map types are probably too difficult, we stripped out this code.
        # serializer.write_col(table_name, "Sexes", "list[str]", [farm.sexes for farm in farms])
        serializer.write_col("min_age_weeks", "float", [farm.min_age_weeks for farm in all_farms])
        serializer.write_col("max_age_weeks", "float", [farm.max_age_weeks for farm in all_farms])
        pre_header_tell = f.tell()
        serializer.finalize()
        print(f"Wrote {f.tell()} bytes to '{db721_file_farms}' (header: {f.tell() - pre_header_tell} bytes).")

    with open(db721_file_chickens, "wb") as f:
        serializer = Db721Serializer("Chicken", f)
        serializer.write_col("identifier", "int", [chicken.identifier for chicken in chickens])
        serializer.write_col("farm_name", "str", [chicken.farm_name for chicken in chickens])
        serializer.write_col("weight_model", "str", [chicken.weight_model for chicken in chickens])
        serializer.write_col("sex", "str", [chicken.sex for chicken in chickens])
        serializer.write_col("age_weeks", "float", [chicken.age_weeks for chicken in chickens])
        serializer.write_col("weight_g", "float", [chicken.weight_grams for chicken in chickens])
        serializer.write_col("notes", "str", [chicken.notes for chicken in chickens])
        pre_header_tell = f.tell()
        serializer.finalize()
        print(f"Wrote {f.tell()} bytes to '{db721_file_farms}' (header: {f.tell() - pre_header_tell} bytes).")

    with open(csv_file_farms, "w", newline="") as f:
        writer = csv.writer(f)
        row = ["Farm Name", "Min Age Weeks", "Max Age Weeks"]
        writer.writerow(row)
        for farm in all_farms:
            writer.writerow([farm.farm_name, farm.min_age_weeks, farm.max_age_weeks])
        print(f"Wrote {f.tell()} bytes to '{csv_file_farms}'.")

    with open(csv_file_chickens, 'w', newline="") as f:
        writer = csv.writer(f)
        row = ["Identifier", "Farm Name", "Weight Model", "Sex", "Age (weeks)", "Weight (g)", "Notes"]
        writer.writerow(row)
        for chicken in chickens:
            row = [chicken.identifier, chicken.farm_name, chicken.weight_model, chicken.sex, chicken.age_weeks,
                   chicken.weight_grams, chicken.notes]
            writer.writerow(row)
        print(f"Wrote {f.tell()} bytes to '{csv_file_chickens}'.")


if __name__ == "__main__":
    main()
