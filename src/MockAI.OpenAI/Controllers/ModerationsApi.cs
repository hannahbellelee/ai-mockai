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
    public class ModerationsApiController : ControllerBase
    { 
        /// <summary>
        /// Classifies if text is potentially harmful.
        /// </summary>
        /// <param name="body"></param>
        /// <response code="200">OK</response>
        [HttpPost]
        [Route("/v1/moderations")]
        [Authorize(AuthenticationSchemes = BearerAuthenticationHandler.SchemeName)]
        [ValidateModelState]
        [SwaggerOperation("CreateModeration")]
        [SwaggerResponse(statusCode: 200, type: typeof(CreateModerationResponse), description: "OK")]
        public virtual IActionResult CreateModeration([FromBody]CreateModerationRequest body)
        { 
            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, default(CreateModerationResponse));
            string exampleJson = null;
            exampleJson = "{\n  \"model\" : \"model\",\n  \"id\" : \"id\",\n  \"results\" : [ {\n    \"category_scores\" : {\n      \"self-harm/intent\" : 2.3021358869347655,\n      \"hate/threatening\" : 6.027456183070403,\n      \"self-harm/instructions\" : 7.061401241503109,\n      \"sexual/minors\" : 3.616076749251911,\n      \"harassment/threatening\" : 5.962133916683182,\n      \"hate\" : 0.8008281904610115,\n      \"self-harm\" : 5.637376656633329,\n      \"harassment\" : 1.4658129805029452,\n      \"sexual\" : 9.301444243932576,\n      \"violence/graphic\" : 4.145608029883936,\n      \"violence\" : 2.027123023002322\n    },\n    \"flagged\" : true,\n    \"categories\" : {\n      \"self-harm/intent\" : true,\n      \"hate/threatening\" : true,\n      \"self-harm/instructions\" : true,\n      \"sexual/minors\" : true,\n      \"harassment/threatening\" : true,\n      \"hate\" : true,\n      \"self-harm\" : true,\n      \"harassment\" : true,\n      \"sexual\" : true,\n      \"violence/graphic\" : true,\n      \"violence\" : true\n    }\n  }, {\n    \"category_scores\" : {\n      \"self-harm/intent\" : 2.3021358869347655,\n      \"hate/threatening\" : 6.027456183070403,\n      \"self-harm/instructions\" : 7.061401241503109,\n      \"sexual/minors\" : 3.616076749251911,\n      \"harassment/threatening\" : 5.962133916683182,\n      \"hate\" : 0.8008281904610115,\n      \"self-harm\" : 5.637376656633329,\n      \"harassment\" : 1.4658129805029452,\n      \"sexual\" : 9.301444243932576,\n      \"violence/graphic\" : 4.145608029883936,\n      \"violence\" : 2.027123023002322\n    },\n    \"flagged\" : true,\n    \"categories\" : {\n      \"self-harm/intent\" : true,\n      \"hate/threatening\" : true,\n      \"self-harm/instructions\" : true,\n      \"sexual/minors\" : true,\n      \"harassment/threatening\" : true,\n      \"hate\" : true,\n      \"self-harm\" : true,\n      \"harassment\" : true,\n      \"sexual\" : true,\n      \"violence/graphic\" : true,\n      \"violence\" : true\n    }\n  } ]\n}";
            
                        var example = exampleJson != null
                        ? JsonConvert.DeserializeObject<CreateModerationResponse>(exampleJson)
                        : default(CreateModerationResponse);            //TODO: Change the data returned
            return new ObjectResult(example);
        }
    }
}