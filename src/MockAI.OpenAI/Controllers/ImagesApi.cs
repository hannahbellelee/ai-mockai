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
    public class ImagesApiController : ControllerBase
    { 
        /// <summary>
        /// Creates an image given a prompt.
        /// </summary>
        /// <param name="body"></param>
        /// <response code="200">OK</response>
        [HttpPost]
        [Route("/v1/images/generations")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("CreateImage")]
        [SwaggerResponse(statusCode: 200, type: typeof(ImagesResponse), description: "OK")]
        public virtual IActionResult CreateImage([FromBody]CreateImageRequest body)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(ImagesResponse));
            string exampleJson = null;
            exampleJson = "{\n  \"data\" : [ {\n    \"revised_prompt\" : \"revised_prompt\",\n    \"b64_json\" : \"b64_json\",\n    \"url\" : \"url\"\n  }, {\n    \"revised_prompt\" : \"revised_prompt\",\n    \"b64_json\" : \"b64_json\",\n    \"url\" : \"url\"\n  } ],\n  \"created\" : 0\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<ImagesResponse>(exampleJson)
                        : default(ImagesResponse);            //TODO: Change the data returned
            return new ObjectResult(example);
        }


    }
}