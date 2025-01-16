# pylint: disable=too-many-arguments, too-many-positional-arguments

"""
Inference Module
"""

from typing import Optional
from pydantic import ValidationError
from langchain_ollama import ChatOllama


class LLMInference:
    """
    A class to handle inference using a large language model (LLM).
    Attributes:
        model (str): The name or path of the model to be used for inference.
        num_predict (int): The number of predictions to generate.
        num_ctx (int): The context length for the model.
        temperature (float, optional): The temperature parameter for controlling
            randomness in predictions. Default is 0.8.
        seed (Optional[int], optional): The seed for random number generation. Default is None.
    Methods:
        __init__(
            model: str, 
            num_predict: int, 
            num_ctx: int, 
            temperature: float = 0.8, 
            seed: Optional[int] = None
        ):
            Initializes the LLMInference instance with the specified parameters.
        invoke_model(prompt: str, output_schema: Any) -> Any:
            Invokes the model with the specified prompt and output schema,
                returning the model's output.
        build_prompt(context: str, query: str) -> str:
            Constructs a prompt by combining the given context and query.
    """

    def __init__(
        self,
        model: str,
        num_predict: int,
        num_ctx: int,
        temperature: float = 0.2,
        seed: Optional[int] = None,
    ):
        self.model = model
        self.temperature = temperature
        self.num_predict = num_predict
        self.num_ctx = num_ctx
        self.seed = seed

    def build_prompt(self, context: str, query: str) -> str:
        """
        Construct a prompt by combining a given context and query.

        Args:
            context (str): The contextual information to include in the prompt.
            query (str): The query or question to append to the context.

        Returns:
            str: A formatted string containing the context and query.
        """
        return f"Use the following context:\n\n```\n{context}\n```\n\n{query}"


    def invoke_model(self, context, query, output_schema):
        """
        Invokes the model with the given prompt and output schema.
        Parameters:
        prompt (str): The input prompt to be processed by the model.
        output_schema (dict): The schema defining the structure of the model's output.
        Returns:
        dict or None: The structured output from the model if successful, otherwise None.
        Raises:
        ValidationError: If the output does not conform to the specified schema.
        """
        model_with_structure = ChatOllama(
            model=self.model,
            temperature=self.temperature,
            num_predict=self.num_predict,
            num_ctx=self.num_ctx,
            seed=self.seed,
        ).with_structured_output(output_schema)

        try:
            return model_with_structure.invoke(self.build_prompt(context, query))
        except ValidationError as e:
            print(f"Validation error: {e}")
            return None
