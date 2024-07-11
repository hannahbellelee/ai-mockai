/*
 * OpenAI API
 *
 * The OpenAI REST API. Please see https://platform.openai.com/docs/api-reference for more details.
 *
 * OpenAPI spec version: 2.1.0
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */
using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using Swashbuckle.AspNetCore.SwaggerGen;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using IO.Swagger.Attributes;
using IO.Swagger.Security;
using Microsoft.AspNetCore.Authorization;
using IO.Swagger.Models;

namespace IO.Swagger.Controllers
{ 
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class VectorStoresApiController : ControllerBase
    { 
        /// <summary>
        /// Cancel a vector store file batch. This attempts to cancel the processing of files in this batch as soon as possible.
        /// </summary>
        /// <param name="vectorStoreId">The ID of the vector store that the file batch belongs to.</param>
        /// <param name="batchId">The ID of the file batch to cancel.</param>
        /// <response code="200">OK</response>
        [HttpPost]
        [Route("/v1/vector_stores/{vector_store_id}/file_batches/{batch_id}/cancel")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("CancelVectorStoreFileBatch")]
        [SwaggerResponse(statusCode: 200, type: typeof(VectorStoreFileBatchObject), description: "OK")]
        public virtual IActionResult CancelVectorStoreFileBatch([FromRoute][Required]string vectorStoreId, [FromRoute][Required]string batchId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(VectorStoreFileBatchObject));
            string exampleJson = null;
            exampleJson = "{\n  \"file_counts\" : {\n    \"in_progress\" : 6,\n    \"total\" : 2,\n    \"cancelled\" : 5,\n    \"completed\" : 1,\n    \"failed\" : 5\n  },\n  \"created_at\" : 0,\n  \"id\" : \"id\",\n  \"object\" : \"vector_store.files_batch\",\n  \"vector_store_id\" : \"vector_store_id\",\n  \"status\" : \"in_progress\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<VectorStoreFileBatchObject>(exampleJson)
                        : default(VectorStoreFileBatchObject);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Create a vector store.
        /// </summary>
        /// <param name="body"></param>
        /// <response code="200">OK</response>
        [HttpPost]
        [Route("/v1/vector_stores")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("CreateVectorStore")]
        [SwaggerResponse(statusCode: 200, type: typeof(VectorStoreObject), description: "OK")]
        public virtual IActionResult CreateVectorStore([FromBody]CreateVectorStoreRequest body)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(VectorStoreObject));
            string exampleJson = null;
            exampleJson = "{\n  \"file_counts\" : {\n    \"in_progress\" : 1,\n    \"total\" : 7,\n    \"cancelled\" : 2,\n    \"completed\" : 5,\n    \"failed\" : 5\n  },\n  \"metadata\" : { },\n  \"expires_at\" : 3,\n  \"expires_after\" : {\n    \"anchor\" : \"last_active_at\",\n    \"days\" : 339\n  },\n  \"last_active_at\" : 2,\n  \"usage_bytes\" : 6,\n  \"name\" : \"name\",\n  \"created_at\" : 0,\n  \"id\" : \"id\",\n  \"object\" : \"vector_store\",\n  \"status\" : \"expired\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<VectorStoreObject>(exampleJson)
                        : default(VectorStoreObject);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Create a vector store file by attaching a [File](/docs/api-reference/files) to a [vector store](/docs/api-reference/vector-stores/object).
        /// </summary>
        /// <param name="body"></param>
        /// <param name="vectorStoreId">The ID of the vector store for which to create a File. </param>
        /// <response code="200">OK</response>
        [HttpPost]
        [Route("/v1/vector_stores/{vector_store_id}/files")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("CreateVectorStoreFile")]
        [SwaggerResponse(statusCode: 200, type: typeof(VectorStoreFileObject), description: "OK")]
        public virtual IActionResult CreateVectorStoreFile([FromBody]CreateVectorStoreFileRequest body, [FromRoute][Required]string vectorStoreId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(VectorStoreFileObject));
            string exampleJson = null;
            exampleJson = "{\n  \"chunking_strategy\" : \"\",\n  \"usage_bytes\" : 0,\n  \"created_at\" : 6,\n  \"id\" : \"id\",\n  \"last_error\" : {\n    \"code\" : \"internal_error\",\n    \"message\" : \"message\"\n  },\n  \"object\" : \"vector_store.file\",\n  \"vector_store_id\" : \"vector_store_id\",\n  \"status\" : \"in_progress\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<VectorStoreFileObject>(exampleJson)
                        : default(VectorStoreFileObject);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Create a vector store file batch.
        /// </summary>
        /// <param name="body"></param>
        /// <param name="vectorStoreId">The ID of the vector store for which to create a File Batch. </param>
        /// <response code="200">OK</response>
        [HttpPost]
        [Route("/v1/vector_stores/{vector_store_id}/file_batches")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("CreateVectorStoreFileBatch")]
        [SwaggerResponse(statusCode: 200, type: typeof(VectorStoreFileBatchObject), description: "OK")]
        public virtual IActionResult CreateVectorStoreFileBatch([FromBody]CreateVectorStoreFileBatchRequest body, [FromRoute][Required]string vectorStoreId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(VectorStoreFileBatchObject));
            string exampleJson = null;
            exampleJson = "{\n  \"file_counts\" : {\n    \"in_progress\" : 6,\n    \"total\" : 2,\n    \"cancelled\" : 5,\n    \"completed\" : 1,\n    \"failed\" : 5\n  },\n  \"created_at\" : 0,\n  \"id\" : \"id\",\n  \"object\" : \"vector_store.files_batch\",\n  \"vector_store_id\" : \"vector_store_id\",\n  \"status\" : \"in_progress\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<VectorStoreFileBatchObject>(exampleJson)
                        : default(VectorStoreFileBatchObject);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Delete a vector store.
        /// </summary>
        /// <param name="vectorStoreId">The ID of the vector store to delete.</param>
        /// <response code="200">OK</response>
        [HttpDelete]
        [Route("/v1/vector_stores/{vector_store_id}")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("DeleteVectorStore")]
        [SwaggerResponse(statusCode: 200, type: typeof(DeleteVectorStoreResponse), description: "OK")]
        public virtual IActionResult DeleteVectorStore([FromRoute][Required]string vectorStoreId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(DeleteVectorStoreResponse));
            string exampleJson = null;
            exampleJson = "{\n  \"deleted\" : true,\n  \"id\" : \"id\",\n  \"object\" : \"vector_store.deleted\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<DeleteVectorStoreResponse>(exampleJson)
                        : default(DeleteVectorStoreResponse);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Delete a vector store file. This will remove the file from the vector store but the file itself will not be deleted. To delete the file, use the [delete file](/docs/api-reference/files/delete) endpoint.
        /// </summary>
        /// <param name="vectorStoreId">The ID of the vector store that the file belongs to.</param>
        /// <param name="fileId">The ID of the file to delete.</param>
        /// <response code="200">OK</response>
        [HttpDelete]
        [Route("/v1/vector_stores/{vector_store_id}/files/{file_id}")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("DeleteVectorStoreFile")]
        [SwaggerResponse(statusCode: 200, type: typeof(DeleteVectorStoreFileResponse), description: "OK")]
        public virtual IActionResult DeleteVectorStoreFile([FromRoute][Required]string vectorStoreId, [FromRoute][Required]string fileId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(DeleteVectorStoreFileResponse));
            string exampleJson = null;
            exampleJson = "{\n  \"deleted\" : true,\n  \"id\" : \"id\",\n  \"object\" : \"vector_store.file.deleted\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<DeleteVectorStoreFileResponse>(exampleJson)
                        : default(DeleteVectorStoreFileResponse);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Retrieves a vector store.
        /// </summary>
        /// <param name="vectorStoreId">The ID of the vector store to retrieve.</param>
        /// <response code="200">OK</response>
        [HttpGet]
        [Route("/v1/vector_stores/{vector_store_id}")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("GetVectorStore")]
        [SwaggerResponse(statusCode: 200, type: typeof(VectorStoreObject), description: "OK")]
        public virtual IActionResult GetVectorStore([FromRoute][Required]string vectorStoreId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(VectorStoreObject));
            string exampleJson = null;
            exampleJson = "{\n  \"file_counts\" : {\n    \"in_progress\" : 1,\n    \"total\" : 7,\n    \"cancelled\" : 2,\n    \"completed\" : 5,\n    \"failed\" : 5\n  },\n  \"metadata\" : { },\n  \"expires_at\" : 3,\n  \"expires_after\" : {\n    \"anchor\" : \"last_active_at\",\n    \"days\" : 339\n  },\n  \"last_active_at\" : 2,\n  \"usage_bytes\" : 6,\n  \"name\" : \"name\",\n  \"created_at\" : 0,\n  \"id\" : \"id\",\n  \"object\" : \"vector_store\",\n  \"status\" : \"expired\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<VectorStoreObject>(exampleJson)
                        : default(VectorStoreObject);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Retrieves a vector store file.
        /// </summary>
        /// <param name="vectorStoreId">The ID of the vector store that the file belongs to.</param>
        /// <param name="fileId">The ID of the file being retrieved.</param>
        /// <response code="200">OK</response>
        [HttpGet]
        [Route("/v1/vector_stores/{vector_store_id}/files/{file_id}")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("GetVectorStoreFile")]
        [SwaggerResponse(statusCode: 200, type: typeof(VectorStoreFileObject), description: "OK")]
        public virtual IActionResult GetVectorStoreFile([FromRoute][Required]string vectorStoreId, [FromRoute][Required]string fileId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(VectorStoreFileObject));
            string exampleJson = null;
            exampleJson = "{\n  \"chunking_strategy\" : \"\",\n  \"usage_bytes\" : 0,\n  \"created_at\" : 6,\n  \"id\" : \"id\",\n  \"last_error\" : {\n    \"code\" : \"internal_error\",\n    \"message\" : \"message\"\n  },\n  \"object\" : \"vector_store.file\",\n  \"vector_store_id\" : \"vector_store_id\",\n  \"status\" : \"in_progress\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<VectorStoreFileObject>(exampleJson)
                        : default(VectorStoreFileObject);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Retrieves a vector store file batch.
        /// </summary>
        /// <param name="vectorStoreId">The ID of the vector store that the file batch belongs to.</param>
        /// <param name="batchId">The ID of the file batch being retrieved.</param>
        /// <response code="200">OK</response>
        [HttpGet]
        [Route("/v1/vector_stores/{vector_store_id}/file_batches/{batch_id}")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("GetVectorStoreFileBatch")]
        [SwaggerResponse(statusCode: 200, type: typeof(VectorStoreFileBatchObject), description: "OK")]
        public virtual IActionResult GetVectorStoreFileBatch([FromRoute][Required]string vectorStoreId, [FromRoute][Required]string batchId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(VectorStoreFileBatchObject));
            string exampleJson = null;
            exampleJson = "{\n  \"file_counts\" : {\n    \"in_progress\" : 6,\n    \"total\" : 2,\n    \"cancelled\" : 5,\n    \"completed\" : 1,\n    \"failed\" : 5\n  },\n  \"created_at\" : 0,\n  \"id\" : \"id\",\n  \"object\" : \"vector_store.files_batch\",\n  \"vector_store_id\" : \"vector_store_id\",\n  \"status\" : \"in_progress\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<VectorStoreFileBatchObject>(exampleJson)
                        : default(VectorStoreFileBatchObject);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Returns a list of vector store files in a batch.
        /// </summary>
        /// <param name="vectorStoreId">The ID of the vector store that the files belong to.</param>
        /// <param name="batchId">The ID of the file batch that the files belong to.</param>
        /// <param name="limit">A limit on the number of objects to be returned. Limit can range between 1 and 100, and the default is 20. </param>
        /// <param name="order">Sort order by the &#x60;created_at&#x60; timestamp of the objects. &#x60;asc&#x60; for ascending order and &#x60;desc&#x60; for descending order. </param>
        /// <param name="after">A cursor for use in pagination. &#x60;after&#x60; is an object ID that defines your place in the list. For instance, if you make a list request and receive 100 objects, ending with obj_foo, your subsequent call can include after&#x3D;obj_foo in order to fetch the next page of the list. </param>
        /// <param name="before">A cursor for use in pagination. &#x60;before&#x60; is an object ID that defines your place in the list. For instance, if you make a list request and receive 100 objects, ending with obj_foo, your subsequent call can include before&#x3D;obj_foo in order to fetch the previous page of the list. </param>
        /// <param name="filter">Filter by file status. One of &#x60;in_progress&#x60;, &#x60;completed&#x60;, &#x60;failed&#x60;, &#x60;cancelled&#x60;.</param>
        /// <response code="200">OK</response>
        [HttpGet]
        [Route("/v1/vector_stores/{vector_store_id}/file_batches/{batch_id}/files")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("ListFilesInVectorStoreBatch")]
        [SwaggerResponse(statusCode: 200, type: typeof(ListVectorStoreFilesResponse), description: "OK")]
        public virtual IActionResult ListFilesInVectorStoreBatch([FromRoute][Required]string vectorStoreId, [FromRoute][Required]string batchId, [FromQuery]int? limit, [FromQuery]string order, [FromQuery]string after, [FromQuery]string before, [FromQuery]string filter)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(ListVectorStoreFilesResponse));
            string exampleJson = null;
            exampleJson = "{\n  \"first_id\" : \"file-abc123\",\n  \"data\" : [ {\n    \"chunking_strategy\" : \"\",\n    \"usage_bytes\" : 0,\n    \"created_at\" : 6,\n    \"id\" : \"id\",\n    \"last_error\" : {\n      \"code\" : \"internal_error\",\n      \"message\" : \"message\"\n    },\n    \"object\" : \"vector_store.file\",\n    \"vector_store_id\" : \"vector_store_id\",\n    \"status\" : \"in_progress\"\n  }, {\n    \"chunking_strategy\" : \"\",\n    \"usage_bytes\" : 0,\n    \"created_at\" : 6,\n    \"id\" : \"id\",\n    \"last_error\" : {\n      \"code\" : \"internal_error\",\n      \"message\" : \"message\"\n    },\n    \"object\" : \"vector_store.file\",\n    \"vector_store_id\" : \"vector_store_id\",\n    \"status\" : \"in_progress\"\n  } ],\n  \"last_id\" : \"file-abc456\",\n  \"has_more\" : false,\n  \"object\" : \"list\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<ListVectorStoreFilesResponse>(exampleJson)
                        : default(ListVectorStoreFilesResponse);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Returns a list of vector store files.
        /// </summary>
        /// <param name="vectorStoreId">The ID of the vector store that the files belong to.</param>
        /// <param name="limit">A limit on the number of objects to be returned. Limit can range between 1 and 100, and the default is 20. </param>
        /// <param name="order">Sort order by the &#x60;created_at&#x60; timestamp of the objects. &#x60;asc&#x60; for ascending order and &#x60;desc&#x60; for descending order. </param>
        /// <param name="after">A cursor for use in pagination. &#x60;after&#x60; is an object ID that defines your place in the list. For instance, if you make a list request and receive 100 objects, ending with obj_foo, your subsequent call can include after&#x3D;obj_foo in order to fetch the next page of the list. </param>
        /// <param name="before">A cursor for use in pagination. &#x60;before&#x60; is an object ID that defines your place in the list. For instance, if you make a list request and receive 100 objects, ending with obj_foo, your subsequent call can include before&#x3D;obj_foo in order to fetch the previous page of the list. </param>
        /// <param name="filter">Filter by file status. One of &#x60;in_progress&#x60;, &#x60;completed&#x60;, &#x60;failed&#x60;, &#x60;cancelled&#x60;.</param>
        /// <response code="200">OK</response>
        [HttpGet]
        [Route("/v1/vector_stores/{vector_store_id}/files")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("ListVectorStoreFiles")]
        [SwaggerResponse(statusCode: 200, type: typeof(ListVectorStoreFilesResponse), description: "OK")]
        public virtual IActionResult ListVectorStoreFiles([FromRoute][Required]string vectorStoreId, [FromQuery]int? limit, [FromQuery]string order, [FromQuery]string after, [FromQuery]string before, [FromQuery]string filter)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(ListVectorStoreFilesResponse));
            string exampleJson = null;
            exampleJson = "{\n  \"first_id\" : \"file-abc123\",\n  \"data\" : [ {\n    \"chunking_strategy\" : \"\",\n    \"usage_bytes\" : 0,\n    \"created_at\" : 6,\n    \"id\" : \"id\",\n    \"last_error\" : {\n      \"code\" : \"internal_error\",\n      \"message\" : \"message\"\n    },\n    \"object\" : \"vector_store.file\",\n    \"vector_store_id\" : \"vector_store_id\",\n    \"status\" : \"in_progress\"\n  }, {\n    \"chunking_strategy\" : \"\",\n    \"usage_bytes\" : 0,\n    \"created_at\" : 6,\n    \"id\" : \"id\",\n    \"last_error\" : {\n      \"code\" : \"internal_error\",\n      \"message\" : \"message\"\n    },\n    \"object\" : \"vector_store.file\",\n    \"vector_store_id\" : \"vector_store_id\",\n    \"status\" : \"in_progress\"\n  } ],\n  \"last_id\" : \"file-abc456\",\n  \"has_more\" : false,\n  \"object\" : \"list\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<ListVectorStoreFilesResponse>(exampleJson)
                        : default(ListVectorStoreFilesResponse);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Returns a list of vector stores.
        /// </summary>
        /// <param name="limit">A limit on the number of objects to be returned. Limit can range between 1 and 100, and the default is 20. </param>
        /// <param name="order">Sort order by the &#x60;created_at&#x60; timestamp of the objects. &#x60;asc&#x60; for ascending order and &#x60;desc&#x60; for descending order. </param>
        /// <param name="after">A cursor for use in pagination. &#x60;after&#x60; is an object ID that defines your place in the list. For instance, if you make a list request and receive 100 objects, ending with obj_foo, your subsequent call can include after&#x3D;obj_foo in order to fetch the next page of the list. </param>
        /// <param name="before">A cursor for use in pagination. &#x60;before&#x60; is an object ID that defines your place in the list. For instance, if you make a list request and receive 100 objects, ending with obj_foo, your subsequent call can include before&#x3D;obj_foo in order to fetch the previous page of the list. </param>
        /// <response code="200">OK</response>
        [HttpGet]
        [Route("/v1/vector_stores")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("ListVectorStores")]
        [SwaggerResponse(statusCode: 200, type: typeof(ListVectorStoresResponse), description: "OK")]
        public virtual IActionResult ListVectorStores([FromQuery]int? limit, [FromQuery]string order, [FromQuery]string after, [FromQuery]string before)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(ListVectorStoresResponse));
            string exampleJson = null;
            exampleJson = "{\n  \"first_id\" : \"vs_abc123\",\n  \"data\" : [ {\n    \"file_counts\" : {\n      \"in_progress\" : 1,\n      \"total\" : 7,\n      \"cancelled\" : 2,\n      \"completed\" : 5,\n      \"failed\" : 5\n    },\n    \"metadata\" : { },\n    \"expires_at\" : 3,\n    \"expires_after\" : {\n      \"anchor\" : \"last_active_at\",\n      \"days\" : 339\n    },\n    \"last_active_at\" : 2,\n    \"usage_bytes\" : 6,\n    \"name\" : \"name\",\n    \"created_at\" : 0,\n    \"id\" : \"id\",\n    \"object\" : \"vector_store\",\n    \"status\" : \"expired\"\n  }, {\n    \"file_counts\" : {\n      \"in_progress\" : 1,\n      \"total\" : 7,\n      \"cancelled\" : 2,\n      \"completed\" : 5,\n      \"failed\" : 5\n    },\n    \"metadata\" : { },\n    \"expires_at\" : 3,\n    \"expires_after\" : {\n      \"anchor\" : \"last_active_at\",\n      \"days\" : 339\n    },\n    \"last_active_at\" : 2,\n    \"usage_bytes\" : 6,\n    \"name\" : \"name\",\n    \"created_at\" : 0,\n    \"id\" : \"id\",\n    \"object\" : \"vector_store\",\n    \"status\" : \"expired\"\n  } ],\n  \"last_id\" : \"vs_abc456\",\n  \"has_more\" : false,\n  \"object\" : \"list\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<ListVectorStoresResponse>(exampleJson)
                        : default(ListVectorStoresResponse);            //TODO: Change the data returned
            return new ObjectResult(example);
        }

        /// <summary>
        /// Modifies a vector store.
        /// </summary>
        /// <param name="body"></param>
        /// <param name="vectorStoreId">The ID of the vector store to modify.</param>
        /// <response code="200">OK</response>
        [HttpPost]
        [Route("/v1/vector_stores/{vector_store_id}")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("ModifyVectorStore")]
        [SwaggerResponse(statusCode: 200, type: typeof(VectorStoreObject), description: "OK")]
        public virtual IActionResult ModifyVectorStore([FromBody]UpdateVectorStoreRequest body, [FromRoute][Required]string vectorStoreId)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(VectorStoreObject));
            string exampleJson = null;
            exampleJson = "{\n  \"file_counts\" : {\n    \"in_progress\" : 1,\n    \"total\" : 7,\n    \"cancelled\" : 2,\n    \"completed\" : 5,\n    \"failed\" : 5\n  },\n  \"metadata\" : { },\n  \"expires_at\" : 3,\n  \"expires_after\" : {\n    \"anchor\" : \"last_active_at\",\n    \"days\" : 339\n  },\n  \"last_active_at\" : 2,\n  \"usage_bytes\" : 6,\n  \"name\" : \"name\",\n  \"created_at\" : 0,\n  \"id\" : \"id\",\n  \"object\" : \"vector_store\",\n  \"status\" : \"expired\"\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<VectorStoreObject>(exampleJson)
                        : default(VectorStoreObject);            //TODO: Change the data returned
            return new ObjectResult(example);
        }
    }
}
